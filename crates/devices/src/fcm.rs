//! FCM HTTP v1 の送信 (W6b-c、Refs ippoan/rust-alc-api#680)。rust の `alc-notify` の `FcmSender::send_data_message` と
//! 同じ JSON (`{"message":{"token","data","android":{"priority":"high"}}}`) を送る。
//!
//! rust は Cloud Run の metadata server から access token を取っていた。Workers にはそれが無いので、FCM の送信専用の
//! service account の鍵 JSON (Secrets Store の `CHIP_REMOTE_FCM_SA_KEY`。ippoan/chip-remote と共有。オーナーの判断) で
//! RS256 の JWT を作り (`alc_worker_crypto::jwt::sign_rs256`)、`oauth2.googleapis.com/token` で access token に替える
//! (ippoan/chip-remote の `src/fcm.rs` と同じ手順)。access token は [`FcmV1`] の中に持ち、同じ要求の中の続く送信で使い回す
//! (worker は要求ごとに [`FcmV1`] を作るので、要求をまたいでは持たない。401 なら捨てて次で取り直す)。
//!
//! 外向きの HTTP は [`FcmHttp`] 越し (Workers では `worker::Fetch`、テストは偽物)。URL は [`FcmV1`] の欄
//! (`token_url`・`send_base`) で、テストでは偽物の URL に差し替える。
//!
//! エラーの文は rust と同じ頭 (`FCM auth error: …` / `FCM send error: …`) だが、相手の応答の本文は載せない
//! (rust は FCM の応答の本文をそのまま載せ、`test-fcm` などの応答に出していた)。

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use alc_worker_crypto::jwt::sign_rs256;
use futures_util::future::BoxFuture;
use futures_util::lock::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::Clock;

/// access token に替える先
pub const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
/// FCM HTTP v1 の頭 (`{send_base}/v1/projects/{project}/messages:send`)
pub const SEND_BASE: &str = "https://fcm.googleapis.com";
/// FCM のプロジェクト (rust-alc-api の本番の `FCM_PROJECT_ID` と同じ。鍵の service account もこのプロジェクトのもの)
pub const PROJECT_ID: &str = "alc-fcm";
/// FCM の送信の scope
pub const FCM_SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";
/// JWT の有効期間 (秒。Google の上限)
pub const JWT_LIFETIME_SECS: i64 = 3600;
/// jwt-bearer の grant (URL エンコード済み)
const GRANT_TYPE: &str = "urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer";

/// data-only の値 (FCM の data はすべて文字列)
pub type Data = BTreeMap<String, String>;

/// 送信の失敗 (rust の `alc_core::fcm::FcmError` と同じ 2 種。文は段の名前と HTTP の status だけ)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FcmError {
    Auth(String),
    Send(String),
}

impl fmt::Display for FcmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Auth(m) => write!(f, "FCM auth error: {m}"),
            Self::Send(m) => write!(f, "FCM send error: {m}"),
        }
    }
}

/// 1 端末への data-only の送信 (Workers では [`FcmV1`]、テストは偽物)
pub trait FcmSend: Send + Sync {
    fn send<'a>(&'a self, token: &'a str, data: Data) -> BoxFuture<'a, Result<(), FcmError>>;
}

pub type SharedFcm = Arc<dyn FcmSend>;

/// HTTP の応答 (status と本文)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub body: String,
}

/// POST だけの HTTP (Workers では `worker::Fetch`、テストは偽物)。届かなかったときは `Err(())`
pub trait FcmHttp: Send + Sync {
    fn post<'a>(
        &'a self,
        url: &'a str,
        headers: Vec<(&'static str, String)>,
        body: String,
    ) -> BoxFuture<'a, Result<HttpResponse, ()>>;
}

/// service account の鍵 JSON の要る欄
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceAccount {
    pub client_email: String,
    pub private_key: String,
    pub project_id: String,
}

#[derive(Deserialize)]
struct KeyJson {
    client_email: Option<String>,
    private_key: Option<String>,
    project_id: Option<String>,
}

impl ServiceAccount {
    /// 鍵 JSON を読む。JSON でない・`client_email` か `private_key` が空なら None (= FCM を送れない。rust の `fcm` が None と同じ)。
    /// project は `project` (rust の `FCM_PROJECT_ID`) > 鍵 JSON の `project_id` の順
    pub fn parse(raw: &str, project: Option<&str>) -> Option<Self> {
        let key: KeyJson = serde_json::from_str(raw.trim()).ok()?;
        let client_email = key.client_email.filter(|s| !s.trim().is_empty())?;
        let private_key = key.private_key.filter(|s| !s.trim().is_empty())?;
        let project_id = project
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .or(key.project_id.filter(|s| !s.trim().is_empty()))?;
        Some(Self {
            client_email: client_email.trim().to_owned(),
            private_key,
            project_id,
        })
    }
}

/// JWT の claim (Google の service account の assertion)
#[derive(Serialize)]
struct Claims<'a> {
    iss: &'a str,
    scope: &'a str,
    aud: &'a str,
    iat: i64,
    exp: i64,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: Option<String>,
}

fn is_success(status: u16) -> bool {
    (200..300).contains(&status)
}

/// FCM HTTP v1 の送信
pub struct FcmV1 {
    account: ServiceAccount,
    http: Arc<dyn FcmHttp>,
    clock: Clock,
    pub token_url: String,
    pub send_base: String,
    /// この要求の中で取った access token
    token: Mutex<Option<String>>,
}

impl FcmV1 {
    pub fn new(account: ServiceAccount, http: Arc<dyn FcmHttp>, clock: Clock) -> Self {
        Self {
            account,
            http,
            clock,
            token_url: TOKEN_URL.to_owned(),
            send_base: SEND_BASE.to_owned(),
            token: Mutex::new(None),
        }
    }

    /// 署名した assertion (`header.claims.signature`)
    pub fn assertion(&self) -> Result<String, FcmError> {
        let iat = (self.clock)() / 1000;
        let claims = Claims {
            iss: &self.account.client_email,
            scope: FCM_SCOPE,
            aud: TOKEN_URL,
            iat,
            exp: iat + JWT_LIFETIME_SECS,
        };
        sign_rs256(&self.account.private_key, None, &claims)
            .map_err(|e| FcmError::Auth(format!("sign ({e})")))
    }

    async fn access_token(&self) -> Result<String, FcmError> {
        let mut cached = self.token.lock().await;
        if let Some(token) = cached.as_ref() {
            return Ok(token.clone());
        }
        let assertion = self.assertion()?;
        let body = format!("grant_type={GRANT_TYPE}&assertion={assertion}");
        let headers = vec![(
            "Content-Type",
            "application/x-www-form-urlencoded".to_owned(),
        )];
        let resp = self
            .http
            .post(&self.token_url, headers, body)
            .await
            .map_err(|()| FcmError::Auth("token request failed".to_owned()))?;
        if !is_success(resp.status) {
            return Err(FcmError::Auth(format!(
                "token exchange returned {}",
                resp.status
            )));
        }
        let token = serde_json::from_str::<TokenResponse>(&resp.body)
            .ok()
            .and_then(|t| t.access_token)
            .filter(|t| !t.is_empty())
            .ok_or_else(|| FcmError::Auth("token response has no access_token".to_owned()))?;
        *cached = Some(token.clone());
        Ok(token)
    }
}

impl FcmSend for FcmV1 {
    fn send<'a>(&'a self, token: &'a str, data: Data) -> BoxFuture<'a, Result<(), FcmError>> {
        Box::pin(async move {
            let access_token = self.access_token().await?;
            let url = format!(
                "{}/v1/projects/{}/messages:send",
                self.send_base, self.account.project_id
            );
            let body = json!({
                "message": { "token": token, "data": data, "android": { "priority": "high" } }
            })
            .to_string();
            let headers = vec![
                ("Authorization", format!("Bearer {access_token}")),
                ("Content-Type", "application/json".to_owned()),
            ];
            let resp = self
                .http
                .post(&url, headers, body)
                .await
                .map_err(|()| FcmError::Send("HTTP request failed".to_owned()))?;
            if is_success(resp.status) {
                return Ok(());
            }
            if resp.status == 401 {
                // access token が失効・取り消された → 次の送信で取り直す
                *self.token.lock().await = None;
            }
            Err(FcmError::Send(format!("FCM API returned {}", resp.status)))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64_decode::decode;
    use rsa::pkcs1v15::{Signature, VerifyingKey};
    use rsa::pkcs8::{EncodePrivateKey, LineEnding};
    use rsa::signature::Verifier;
    use rsa::RsaPrivateKey;
    use sha2::Sha256;
    use std::collections::VecDeque;
    use std::sync::{Mutex as StdMutex, OnceLock};

    /// base64url (padding なし) の復号 (テスト専用の小さな実装)
    mod base64_decode {
        pub fn decode(s: &str) -> Vec<u8> {
            const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
            let mut out = Vec::new();
            let (mut buf, mut bits) = (0u32, 0u32);
            for c in s.bytes() {
                let v = T.iter().position(|&x| x == c).unwrap() as u32;
                buf = (buf << 6) | v;
                bits += 6;
                if bits >= 8 {
                    bits -= 8;
                    out.push((buf >> bits) as u8);
                    buf &= (1 << bits) - 1;
                }
            }
            out
        }
    }

    /// テスト用の鍵 (生成は重いので 1 回だけ。1024 bit = テスト専用の大きさ)
    fn key() -> &'static RsaPrivateKey {
        static KEY: OnceLock<RsaPrivateKey> = OnceLock::new();
        KEY.get_or_init(|| RsaPrivateKey::new(&mut rand::thread_rng(), 1024).unwrap())
    }

    fn pem() -> String {
        key().to_pkcs8_pem(LineEnding::LF).unwrap().to_string()
    }

    fn account() -> ServiceAccount {
        ServiceAccount {
            client_email: "sender@test.invalid".to_owned(),
            private_key: pem(),
            project_id: "proj-1".to_owned(),
        }
    }

    /// 偽の HTTP が受けた (URL, ヘッダー, 本文)
    type Seen = (String, Vec<(&'static str, String)>, String);
    /// 偽の HTTP の返す応答 (status と本文。`Err` は届かない)
    type Reply<'a> = Result<(u16, &'a str), ()>;

    #[derive(Default)]
    struct FakeHttp {
        replies: StdMutex<VecDeque<Result<HttpResponse, ()>>>,
        seen: StdMutex<Vec<Seen>>,
    }

    impl FakeHttp {
        fn with(replies: Vec<Reply<'_>>) -> Arc<Self> {
            let r = replies
                .into_iter()
                .map(|x| {
                    x.map(|(status, body)| HttpResponse {
                        status,
                        body: body.to_owned(),
                    })
                })
                .collect();
            Arc::new(Self {
                replies: StdMutex::new(r),
                seen: StdMutex::default(),
            })
        }
    }

    impl FcmHttp for FakeHttp {
        fn post<'a>(
            &'a self,
            url: &'a str,
            headers: Vec<(&'static str, String)>,
            body: String,
        ) -> BoxFuture<'a, Result<HttpResponse, ()>> {
            self.seen
                .lock()
                .unwrap()
                .push((url.to_owned(), headers, body));
            let reply = self.replies.lock().unwrap().pop_front().unwrap();
            Box::pin(async move { reply })
        }
    }

    const TOKEN_OK: (u16, &str) = (200, r#"{"access_token":"at-1","expires_in":3599}"#);

    fn sender(http: Arc<FakeHttp>) -> FcmV1 {
        let mut s = FcmV1::new(account(), http, Arc::new(|| 1_800_000_000_123));
        s.token_url = "http://token.test/token".to_owned();
        s.send_base = "http://fcm.test".to_owned();
        s
    }

    fn data() -> Data {
        Data::from([("type".to_owned(), "test".to_owned())])
    }

    #[test]
    fn parse_reads_key_json() {
        let raw = |v: serde_json::Value| v.to_string();
        let full =
            raw(json!({ "client_email": " a@b ", "private_key": "pem", "project_id": "from-key" }));
        assert_eq!(
            ServiceAccount::parse(&full, Some("alc-fcm")),
            Some(ServiceAccount {
                client_email: "a@b".to_owned(),
                private_key: "pem".to_owned(),
                project_id: "alc-fcm".to_owned(),
            })
        );
        assert_eq!(
            ServiceAccount::parse(&full, Some(" ")).map(|a| a.project_id),
            Some("from-key".to_owned())
        );
        assert_eq!(
            ServiceAccount::parse(&full, None).map(|a| a.project_id),
            Some("from-key".to_owned())
        );
        for bad in [
            "not json".to_owned(),
            raw(json!({ "private_key": "pem", "project_id": "p" })),
            raw(json!({ "client_email": "a@b", "private_key": " ", "project_id": "p" })),
            raw(json!({ "client_email": "a@b", "private_key": "pem" })),
        ] {
            assert_eq!(ServiceAccount::parse(&bad, None), None, "{bad}");
        }
    }

    #[test]
    fn error_text_has_rust_prefixes() {
        assert_eq!(FcmError::Auth("x".into()).to_string(), "FCM auth error: x");
        assert_eq!(FcmError::Send("y".into()).to_string(), "FCM send error: y");
    }

    #[tokio::test]
    async fn sends_with_a_signed_assertion_and_reuses_the_token() {
        let http = FakeHttp::with(vec![Ok(TOKEN_OK), Ok((200, "{}")), Ok((200, "{}"))]);
        let s = sender(http.clone());
        assert_eq!(s.send("tok-a", data()).await, Ok(()));
        assert_eq!(s.send("tok-b", data()).await, Ok(()));
        let seen = http.seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 3, "access token は 1 回だけ取る");

        // token の交換: form の grant_type と、鍵で検証できる assertion
        let (url, headers, body) = &seen[0];
        assert_eq!(url, "http://token.test/token");
        assert_eq!(
            headers,
            &vec![(
                "Content-Type",
                "application/x-www-form-urlencoded".to_owned()
            )]
        );
        let assertion = body
            .strip_prefix(
                "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=",
            )
            .unwrap();
        let parts: Vec<&str> = assertion.split('.').collect();
        assert_eq!(parts.len(), 3);
        let header: serde_json::Value = serde_json::from_slice(&decode(parts[0])).unwrap();
        assert_eq!(header, json!({ "alg": "RS256", "typ": "JWT" }));
        let claims: serde_json::Value = serde_json::from_slice(&decode(parts[1])).unwrap();
        assert_eq!(
            claims,
            json!({
                "iss": "sender@test.invalid",
                "scope": FCM_SCOPE,
                "aud": TOKEN_URL,
                "iat": 1_800_000_000,
                "exp": 1_800_003_600,
            })
        );
        let sig = Signature::try_from(decode(parts[2]).as_slice()).unwrap();
        VerifyingKey::<Sha256>::new(key().to_public_key())
            .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &sig)
            .unwrap();

        // 送信: FCM HTTP v1 の URL・Bearer・rust と同じ JSON
        let (url, headers, body) = &seen[1];
        assert_eq!(url, "http://fcm.test/v1/projects/proj-1/messages:send");
        assert_eq!(
            headers,
            &vec![
                ("Authorization", "Bearer at-1".to_owned()),
                ("Content-Type", "application/json".to_owned()),
            ]
        );
        let body: serde_json::Value = serde_json::from_str(body).unwrap();
        assert_eq!(
            body,
            json!({ "message": { "token": "tok-a", "data": { "type": "test" }, "android": { "priority": "high" } } })
        );
    }

    #[tokio::test]
    async fn token_failures_are_auth_errors() {
        let cases: Vec<(Vec<Reply<'_>>, &str)> = vec![
            (vec![Err(())], "token request failed"),
            (vec![Ok((500, "{}"))], "token exchange returned 500"),
            (vec![Ok((200, "{}"))], "token response has no access_token"),
            (
                vec![Ok((200, r#"{"access_token":""}"#))],
                "token response has no access_token",
            ),
            (
                vec![Ok((200, "not json"))],
                "token response has no access_token",
            ),
        ];
        for (replies, want) in cases {
            let s = sender(FakeHttp::with(replies));
            assert_eq!(
                s.send("t", data()).await,
                Err(FcmError::Auth(want.to_owned()))
            );
        }
        // 鍵が読めない
        let mut bad = sender(FakeHttp::with(vec![]));
        bad.account.private_key = "not a pem".to_owned();
        assert_eq!(
            bad.assertion(),
            Err(FcmError::Auth("sign (key)".to_owned()))
        );
    }

    #[tokio::test]
    async fn send_failures_are_send_errors_and_401_drops_the_token() {
        let http = FakeHttp::with(vec![
            Ok(TOKEN_OK),
            Ok((404, r#"{"error":"UNREGISTERED tok-a"}"#)),
            Err(()),
            Ok((401, "{}")),
            Ok(TOKEN_OK),
            Ok((200, "{}")),
        ]);
        let s = sender(http.clone());
        assert_eq!(
            s.send("tok-a", data()).await,
            Err(FcmError::Send("FCM API returned 404".to_owned()))
        );
        assert_eq!(
            s.send("tok-a", data()).await,
            Err(FcmError::Send("HTTP request failed".to_owned()))
        );
        assert_eq!(
            s.send("tok-a", data()).await,
            Err(FcmError::Send("FCM API returned 401".to_owned()))
        );
        // 401 の後は access token を取り直す
        assert_eq!(s.send("tok-a", data()).await, Ok(()));
        let urls: Vec<String> = http
            .seen
            .lock()
            .unwrap()
            .iter()
            .map(|r| r.0.clone())
            .collect();
        assert_eq!(urls.iter().filter(|u| u.contains("token")).count(), 2);
    }
}
