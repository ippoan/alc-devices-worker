//! 端末の登録・管理の口 (W6b、Refs ippoan/rust-alc-api#680)。rust-alc-api の `crates/alc-devices` の devices.rs・
//! repo/devices.rs と `alc-core` の repository/devices.rs の写しで、path・method・JSON の形・status は rust と同じ
//! (alc-app の管理画面・AlcoholChecker 端末・auth-worker がそのまま使う)。
//!
//! - [`devices`] — 管理画面の口 (一覧・承認待ち・登録用のコードの発行・承認・却下・停止・再開・削除・着信の設定) と、
//!   端末の口 (登録の申請・状態・受け取り・設定・最終ログイン・版と watchdog の報告・FCM token の登録)、
//!   auth-worker の内部の口 (`/internal/devices/{device_id}/pairing-tenant`)
//! - [`re_pair`] — kiosk 端末の再ペアリング (管理画面の window を開ける口と、端末の取り直しの口。発行は auth-worker の RPC) (W6b-b)
//! - [`notify`] — FCM で端末に送る 7 口 (着信の通知・試験の送信と閉じる・OTA) (W6b-c)。送信は [`fcm`] (FCM HTTP v1)
//!
//! **管理画面の口だけが `X-Tenant-ID` を要る** (auth-worker が付ける。無い・UUID でない → 401。
//! `alc_core_wasm::require_tenant_header`。承認者は `X-User-ID` 等から取る)。端末の口と内部の口は rust でも
//! テナントの認証を持たず、テナントは端末の ID から SECURITY DEFINER の関数で引く (rust と同じ)。
//! DB は `PgClient::tenant_tx` + `query_typed` 系だけ (名前付き prepared statement は使わない)。テナントの決まる前の
//! 文は、テナントに依らない文 (SECURITY DEFINER の関数・USING (true) の登録の表) だけを nil のテナントの transaction で流す。
//! ログ・エラー応答は固定の語だけ (端末の ID・コード・社員の名前・エラーの文を載せない)。

pub mod devices;
pub mod fcm;
pub mod notify;
pub mod re_pair;

use std::sync::Arc;

use alc_core_wasm::require_tenant_header;
use alc_worker_db::{kind, PgClient};
use axum::http::StatusCode;
use axum::middleware;
use axum::Router;
use futures_util::lock::Mutex;

pub type LogSink = Arc<dyn Fn(&str) + Send + Sync>;

/// 今の時刻 (unix ms)。Workers では `Date.now()`、テストは固定の値 (着信の時間帯の判定と FCM の data の timestamp・JWT の iat)
pub type Clock = Arc<dyn Fn() -> i64 + Send + Sync>;

#[derive(Clone)]
pub struct AppState {
    pub pg: Arc<Mutex<PgClient>>,
    pub log: LogSink,
    /// 再ペアリングの credential の発行 (auth-worker の binding が無ければ None = rust と同じく 404)
    pub pairer: Option<re_pair::SharedPairer>,
    /// FCM の送信 (鍵が無ければ None = rust と同じく FCM の口は 503。着信の設定の通知は送らない)
    pub fcm: Option<fcm::SharedFcm>,
    /// `X-Internal-Secret` と比べる値 (worker は Secrets Store の `INTERNAL_SHARED_SECRET`。無ければ None = 照合する口は 503。fail-closed)
    pub internal_secret: Option<String>,
    pub clock: Clock,
}

impl AppState {
    /// DB の失敗を固定の語でログに出し、500 にする
    fn db_fail(&self, stage: &str, e: &tokio_postgres::Error) -> StatusCode {
        (self.log)(&format!("devices: {stage} failed: db ({})", kind(e)));
        StatusCode::INTERNAL_SERVER_ERROR
    }
}

/// 全部の口。rust と同じく `/api` の下 (auth-worker は `/api/...` のまま Service Binding に渡す)
pub fn router() -> Router<AppState> {
    let tenant = devices::tenant_router()
        .merge(re_pair::tenant_router())
        .merge(notify::tenant_router())
        .route_layer(middleware::from_fn(require_tenant_header));
    let api = tenant
        .merge(devices::public_router())
        .merge(re_pair::public_router())
        .merge(notify::public_router());
    Router::new().nest("/api", api)
}
