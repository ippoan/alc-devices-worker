//! 端末の登録・管理の Worker `alc-devices` (Refs ippoan/rust-alc-api#680)。crates/devices の口
//! (`router`、axum) を workers-rs (`http` / `axum` feature) に載せる。型は ippoan/alc-people-worker と同じ。
//! DB への経路 (staging = Workers VPC の先の PgBouncer、本番 = Hyperdrive) は [`db::connect`] の 1 か所で出し分ける。
//!
//! **この Worker は呼び手を認証しない。** 本番・staging とも workers.dev を開けず (`workers_dev` / `preview_urls` = false、
//! `routes` を持たない)、入口は auth-worker からの Service Binding だけ (wrangler.toml と scripts/check-exposure.sh が保証する)。

// worker 本体は wasm32 専用。native の `cargo build` / `clippy` / `test` (workspace の root で打つもの) では空の crate にして、
// crates/devices だけを検査させる
#![cfg(target_arch = "wasm32")]

mod db;
mod fcm;
mod pair;
mod tcp;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{HeaderValue, Response, StatusCode};
use devices::{router, AppState, LogSink};
use futures_util::lock::Mutex;
use tower_service::Service;
use worker::{console_error, event, Context, Env, HttpRequest, Result, WorkerVersionMetadata};

fn log_sink() -> LogSink {
    Arc::new(|message| console_error!("{message}"))
}

fn error_response(status: StatusCode, code: &str) -> Response<Body> {
    let mut resp = Response::new(Body::from(format!(r#"{{"error":"{code}"}}"#)));
    *resp.status_mut() = status;
    resp
}

#[event(fetch)]
async fn fetch(req: HttpRequest, env: Env, _ctx: Context) -> Result<Response<Body>> {
    // 全リクエストで routing の前に繋ぐ (ippoan/alc-people-worker と同じ)
    let pg = match db::connect(&env).await {
        Ok(c) => c,
        Err(db::ConnectError::NotConfigured) => {
            console_error!("devices: {}", db::ConnectError::NotConfigured);
            return Ok(error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "database_not_configured",
            ));
        }
        Err(e) => {
            console_error!("devices: {e}");
            return Ok(error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
            ));
        }
    };
    let clock: devices::Clock = Arc::new(|| js_sys::Date::now() as i64);
    let state = AppState {
        pg: Arc::new(Mutex::new(pg)),
        log: log_sink(),
        // 本番だけの Secrets Store の binding。無い env (staging・local) では FCM の口は rust と同じく 503
        fcm: fcm::sender(&env, clock.clone()).await,
        // FCM_INTERNAL_SECRET (X-Internal-Secret の照合)。本番の rust-alc-api にも無く、無ければ照合する口は 503 (fail-closed)
        internal_secret: env
            .secret("FCM_INTERNAL_SECRET")
            .ok()
            .map(|s| s.to_string()),
        clock,
        // 本番だけの binding。無い env (staging・local) では再ペアリングは rust と同じく 404
        pairer: env
            .service("AUTH_DEVICE_PAIR")
            .ok()
            .map(|f| Arc::new(pair::AuthDevicePairer::new(f)) as devices::re_pair::SharedPairer),
    };
    let mut resp = match router().with_state(state).call(req).await {
        Ok(r) => r,
        Err(e) => match e {},
    };
    // どの版が応えたかを応答ヘッダーで分かるようにする。binding が取れなければ何も付けない
    if let Ok(meta) = env.get_binding::<WorkerVersionMetadata>("CF_VERSION_METADATA") {
        if let Ok(v) = HeaderValue::from_str(&meta.id()) {
            resp.headers_mut().insert("x-worker-version", v);
        }
        let tag = meta.tag();
        if !tag.is_empty() {
            if let Ok(v) = HeaderValue::from_str(&tag) {
                resp.headers_mut().insert("x-worker-tag", v);
            }
        }
    }
    Ok(resp)
}
