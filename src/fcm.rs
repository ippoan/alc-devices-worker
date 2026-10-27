//! FCM の送信 (`devices::fcm::FcmV1`) の Workers での部品: 鍵 (Secrets Store の `CHIP_REMOTE_FCM_SA_KEY`、本番だけ) と
//! 外向きの HTTP (`worker::Fetch`)。鍵が無い・読めないときは None (= FCM の口は rust と同じく 503)。
//!
//! 値と future は JS の値で `Send` でないので、`worker::send` の `SendFuture` で包む (Workers は単一 thread)。
//! このファイルは wasm 専用で、CI のテストと coverage の gate の外 (確かめるのは本番の実物)。

use std::sync::Arc;

use devices::fcm::{FcmHttp, FcmV1, HttpResponse, ServiceAccount, SharedFcm, PROJECT_ID};
use devices::Clock;
use futures_util::future::BoxFuture;
use wasm_bindgen::JsValue;
use worker::send::SendFuture;
use worker::{Env, Fetch, Headers, Method, Request, RequestInit};

/// 鍵の Secrets Store の binding (ippoan/chip-remote と共有する FCM の送信専用の service account の鍵 JSON)
pub const KEY_BINDING: &str = "CHIP_REMOTE_FCM_SA_KEY";

struct WorkerHttp;

async fn post(
    url: &str,
    headers: Vec<(&'static str, String)>,
    body: String,
) -> worker::Result<HttpResponse> {
    let h = Headers::new();
    for (k, v) in headers {
        h.set(k, &v)?;
    }
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(h)
        .with_body(Some(JsValue::from_str(&body)));
    let req = Request::new_with_init(url, &init)?;
    let mut resp = Fetch::Request(req).send().await?;
    Ok(HttpResponse {
        status: resp.status_code(),
        body: resp.text().await?,
    })
}

impl FcmHttp for WorkerHttp {
    fn post<'a>(
        &'a self,
        url: &'a str,
        headers: Vec<(&'static str, String)>,
        body: String,
    ) -> BoxFuture<'a, Result<HttpResponse, ()>> {
        Box::pin(SendFuture::new(async move {
            post(url, headers, body).await.map_err(|_| ())
        }))
    }
}

/// 鍵を読んで送信の部品を作る (binding が無い env = staging・local では None)
pub async fn sender(env: &Env, clock: Clock) -> Option<SharedFcm> {
    let store = env.secret_store(KEY_BINDING).ok()?;
    let raw = SendFuture::new(store.get()).await.ok()??;
    let account = ServiceAccount::parse(&raw, Some(PROJECT_ID))?;
    Some(Arc::new(FcmV1::new(account, Arc::new(WorkerHttp), clock)) as SharedFcm)
}
