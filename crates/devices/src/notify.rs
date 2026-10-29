//! FCM で端末に送る口 (W6b-c、Refs ippoan/rust-alc-api#680。rust の `alc-devices` の devices.rs の FCM の 7 口の写し)。
//! path・method・JSON の形・status は rust と同じ。送信は [`crate::fcm`] (鍵が無い = `AppState::fcm` が None のときの status も rust と同じ)。
//!
//! 端末・内部の口 (rust では公開。テナントのヘッダーを要らない):
//! - `POST /devices/fcm-notify-call` — 着信の通知 (全テナントの、着信を受ける設定の端末へ。`X-Internal-Secret` を照合)
//! - `POST /devices/fcm-dismiss-test` — 試験の通知を閉じる (端末のテナントのほかの端末へ。認証なし = rust と同じ)
//! - `POST /devices/test-fcm-all-exclude` — 試験の送信 (全テナントの着信を受ける端末へ。`X-Internal-Secret` を照合)
//! - `POST /devices/trigger-update-dev` — dev 端末の OTA (全テナントの dev 端末へ。`X-Internal-Secret` を照合)
//!
//! 管理画面の口 (`X-Tenant-ID` 必須):
//! - `POST /devices/{id}/test-fcm` — 1 台へ試験の送信。`POST /devices/test-fcm-all` — テナントの全端末へ
//! - `POST /devices/trigger-update` — テナントの端末の OTA
//!
//! `X-Internal-Secret` は照合の値 (worker は Secrets Store の `INTERNAL_SHARED_SECRET`、本番だけ) と定数時間で比べる。
//! **設定が無ければ 503** (fail-closed)。rust-alc-api の頃は照合の値 `FCM_INTERNAL_SECRET` が本番に無く、着信の FCM は届いていなかった。
//! 呼び手は cf-alc-signaling (Service Binding。同じ INTERNAL_SHARED_SECRET を載せる。Refs ippoan/rust-alc-api#680)。
//! 全テナントを横断する読み取りは SECURITY DEFINER の関数 (migration 158) だけを nil のテナントの transaction で流す。
//! 送り終えてから応答する (fire-and-forget にしない)。
//!
//! rust との違い:
//! - 失敗の応答 (`error`) とログに FCM の応答の本文を載せない ([`crate::fcm`])。ログは固定の語と件数だけ (端末の ID を出さない)
//! - 一覧の文に並びを足した (端末の ID の順。rust は並びを決めていなかった)

use std::collections::HashSet;

use alc_core_wasm::TenantId;
use alc_worker_db::{PgClient, TxOutput};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use axum::{Extension, Json, Router};
use chrono::{DateTime, Datelike, FixedOffset, Timelike};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio_postgres::types::Type;
use tokio_postgres::Error;
use uuid::Uuid;

use crate::fcm::{Data, FcmSend};
use crate::AppState;

pub mod sql {
    /// 全テナントの、有効で FCM token の在る端末 (着信の通知の対象)。SECURITY DEFINER の関数
    pub const LIST_FCM_DEVICES: &str =
        "SELECT id, fcm_token, call_enabled, call_schedule FROM alc_api.list_fcm_devices() ORDER BY id";

    /// 全テナントの、着信を受ける端末 (試験の送信の対象)。SECURITY DEFINER の関数
    pub const LIST_ALL_CALLABLE: &str =
        "SELECT id, device_name, fcm_token FROM alc_api.list_all_callable_devices() ORDER BY id";

    /// dev 端末の在るテナント。SECURITY DEFINER の関数
    pub const LIST_DEV_TENANTS: &str =
        "SELECT t FROM alc_api.list_dev_device_tenant_ids() t ORDER BY t";

    /// テナントのほかの端末の FCM token。$1 tenant_id / $2 除く端末
    pub const TENANT_TOKENS_EXCEPT: &str = "SELECT fcm_token FROM alc_api.devices \
          WHERE tenant_id = $1 AND id <> $2 AND status = 'active' AND fcm_token IS NOT NULL ORDER BY id";

    /// 1 台の FCM token (行が無ければ 0 行、token が無ければ NULL)。$1 tenant_id / $2 id
    pub const DEVICE_FCM_TOKEN: &str =
        "SELECT fcm_token FROM alc_api.devices WHERE tenant_id = $1 AND id = $2";

    /// テナントの、有効で FCM token の在る端末。$1 tenant_id
    pub const TENANT_FCM_DEVICES: &str = "SELECT id, device_name, fcm_token FROM alc_api.devices \
          WHERE tenant_id = $1 AND status = 'active' AND fcm_token IS NOT NULL ORDER BY id";

    /// OTA の対象 (dev だけかどうか)。$1 tenant_id / $2 dev だけ
    pub const OTA_DEVICES: &str =
        "SELECT id, device_name, fcm_token, app_version_code FROM alc_api.devices \
          WHERE tenant_id = $1 AND status = 'active' AND fcm_token IS NOT NULL \
            AND (NOT $2 OR is_dev_device = true) ORDER BY id";
}

// --- 行 ---

/// 着信の通知の対象 (rust の `FcmDeviceRow`)
#[derive(Debug, Clone, PartialEq)]
pub struct FcmDevice {
    pub id: Uuid,
    pub fcm_token: String,
    pub call_enabled: bool,
    pub call_schedule: Option<Value>,
}

impl TxOutput for FcmDevice {}

/// 送る端末 (rust の `FcmTestDeviceRow`・`OtaDeviceRow`。OTA でないときの版は None)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetDevice {
    pub id: Uuid,
    pub device_name: String,
    pub fcm_token: String,
    pub app_version_code: Option<i32>,
}

impl TxOutput for TargetDevice {}

// --- DB ---

pub async fn list_fcm_devices(pg: &mut PgClient) -> Result<Vec<FcmDevice>, Error> {
    pg.tenant_tx(Uuid::nil(), |tx| {
        Box::pin(async move {
            let rows = tx.query_typed(sql::LIST_FCM_DEVICES, &[]).await?;
            Ok(rows
                .iter()
                .map(|r| FcmDevice {
                    id: r.get(0),
                    fcm_token: r.get(1),
                    call_enabled: r.get(2),
                    call_schedule: r.get(3),
                })
                .collect())
        })
    })
    .await
}

fn target(r: &tokio_postgres::Row, with_version: bool) -> TargetDevice {
    TargetDevice {
        id: r.get(0),
        device_name: r.get(1),
        fcm_token: r.get(2),
        app_version_code: if with_version { r.get(3) } else { None },
    }
}

pub async fn list_all_callable(pg: &mut PgClient) -> Result<Vec<TargetDevice>, Error> {
    pg.tenant_tx(Uuid::nil(), |tx| {
        Box::pin(async move {
            let rows = tx.query_typed(sql::LIST_ALL_CALLABLE, &[]).await?;
            Ok(rows.iter().map(|r| target(r, false)).collect())
        })
    })
    .await
}

pub async fn list_dev_tenants(pg: &mut PgClient) -> Result<Vec<Uuid>, Error> {
    pg.tenant_tx(Uuid::nil(), |tx| {
        Box::pin(async move {
            let rows = tx.query_typed(sql::LIST_DEV_TENANTS, &[]).await?;
            Ok(rows.iter().map(|r| r.get(0)).collect())
        })
    })
    .await
}

/// 端末が有効ならそのテナントの、ほかの端末の FCM token。端末が無い・有効でなければ None
pub async fn dismiss_targets(
    pg: &mut PgClient,
    device_id: Uuid,
) -> Result<Option<Vec<String>>, Error> {
    let state = pg
        .tenant_tx(Uuid::nil(), move |tx| {
            Box::pin(async move { crate::devices::re_pair_state(tx, device_id).await })
        })
        .await?;
    let Some((tenant_id, _, _)) = state.filter(|(_, status, _)| status == "active") else {
        return Ok(None);
    };
    let tokens = pg
        .tenant_tx(tenant_id, move |tx| {
            Box::pin(async move {
                let rows = tx
                    .query_typed(
                        sql::TENANT_TOKENS_EXCEPT,
                        &[(&tenant_id, Type::UUID), (&device_id, Type::UUID)],
                    )
                    .await?;
                Ok(rows.iter().map(|r| r.get::<_, String>(0)).collect())
            })
        })
        .await?;
    Ok(Some(tokens))
}

/// 1 台の FCM token。行が無ければ None、token が無ければ Some(None)
pub async fn device_fcm_token(
    pg: &mut PgClient,
    tenant_id: Uuid,
    id: Uuid,
) -> Result<Option<Option<String>>, Error> {
    pg.tenant_tx(tenant_id, move |tx| {
        Box::pin(async move {
            Ok(tx
                .query_typed_opt(
                    sql::DEVICE_FCM_TOKEN,
                    &[(&tenant_id, Type::UUID), (&id, Type::UUID)],
                )
                .await?
                .map(|r| r.get(0)))
        })
    })
    .await
}

pub async fn tenant_fcm_devices(
    pg: &mut PgClient,
    tenant_id: Uuid,
) -> Result<Vec<TargetDevice>, Error> {
    pg.tenant_tx(tenant_id, move |tx| {
        Box::pin(async move {
            let rows = tx
                .query_typed(sql::TENANT_FCM_DEVICES, &[(&tenant_id, Type::UUID)])
                .await?;
            Ok(rows.iter().map(|r| target(r, false)).collect())
        })
    })
    .await
}

pub async fn ota_devices(
    pg: &mut PgClient,
    tenant_id: Uuid,
    dev_only: bool,
) -> Result<Vec<TargetDevice>, Error> {
    pg.tenant_tx(tenant_id, move |tx| {
        Box::pin(async move {
            let rows = tx
                .query_typed(
                    sql::OTA_DEVICES,
                    &[(&tenant_id, Type::UUID), (&dev_only, Type::BOOL)],
                )
                .await?;
            Ok(rows.iter().map(|r| target(r, true)).collect())
        })
    })
    .await
}

// --- 判定 ---

/// 着信の時間帯の判定 (rust の `should_notify_device`。JST で曜日 0 = 日〜6 = 土・時分を見る)
pub fn should_notify(call_enabled: bool, schedule: Option<&Value>, now_ms: i64) -> bool {
    if !call_enabled {
        return false;
    }
    let Some(schedule) = schedule else {
        return true;
    };
    if !schedule
        .get("enabled")
        .and_then(Value::as_bool)
        .unwrap_or(true)
    {
        return false;
    }
    let jst = FixedOffset::east_opt(9 * 3600).unwrap_or_else(|| unreachable!());
    let now = DateTime::from_timestamp_millis(now_ms)
        .unwrap_or_default()
        .with_timezone(&jst);
    let day = i64::from(now.weekday().num_days_from_sunday());
    let days: Vec<i64> = schedule
        .get("days")
        .and_then(Value::as_array)
        .map(|d| d.iter().filter_map(Value::as_i64).collect())
        .unwrap_or_default();
    if !days.is_empty() && !days.contains(&day) {
        return false;
    }
    let num =
        |key: &str, default: i64| schedule.get(key).and_then(Value::as_i64).unwrap_or(default);
    let current = i64::from(now.hour() * 60 + now.minute());
    let start = num("startHour", 0) * 60 + num("startMin", 0);
    let end = num("endHour", 24) * 60 + num("endMin", 0);
    if start <= end {
        current >= start && current < end
    } else {
        current >= start || current < end
    }
}

/// `X-Internal-Secret` を照合の値 (`INTERNAL_SHARED_SECRET`) と比べる。設定が無ければ 503 (fail-closed)、違えば 401
pub fn check_internal_secret(
    expected: Option<&str>,
    headers: &HeaderMap,
) -> Result<(), StatusCode> {
    let expected = expected.ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let provided = headers
        .get("X-Internal-Secret")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if crate::devices::constant_time_eq(provided, expected) {
        Ok(())
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

/// `type` と (あれば) `timestamp` の data
fn data(kind: &str, timestamp: Option<i64>) -> Data {
    let mut d = Data::new();
    d.insert("type".to_owned(), kind.to_owned());
    if let Some(ts) = timestamp {
        d.insert("timestamp".to_owned(), ts.to_string());
    }
    d
}

impl AppState {
    fn fcm_or_503(&self) -> Result<&dyn FcmSend, StatusCode> {
        self.fcm.as_deref().ok_or(StatusCode::SERVICE_UNAVAILABLE)
    }
}

/// 着信の設定で always_on・bp_enabled が変わったとき、端末に設定を取り直させる (rust の `settings_changed`)。
/// FCM が無い・token が無い・送れないときは何もしない (応答は 204 のまま = rust と同じ)
pub async fn notify_settings_changed(state: &AppState, tenant_id: Uuid, id: Uuid) {
    let Some(fcm) = state.fcm.as_deref() else {
        return;
    };
    let token = {
        let mut pg = state.pg.lock().await;
        device_fcm_token(&mut pg, tenant_id, id).await
    };
    let Ok(Some(Some(token))) = token else {
        return;
    };
    let d = data("settings_changed", Some((state.clock)()));
    if fcm.send(&token, d).await.is_err() {
        (state.log)("devices: settings_changed fcm failed");
    }
}

// --- 本文と応答 ---

#[derive(Debug, Deserialize)]
pub struct FcmNotifyCallBody {
    pub room_ids: Vec<String>,
    #[serde(default)]
    pub exclude_device_ids: Vec<String>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct FcmNotifyCallResponse {
    pub sent: usize,
    pub skipped: usize,
    pub errors: usize,
}

#[derive(Debug, Deserialize)]
pub struct FcmDismissTestBody {
    pub device_id: Uuid,
}

#[derive(Debug, Deserialize)]
pub struct TestFcmAllExcludeBody {
    #[serde(default)]
    pub exclude_device_ids: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct TestFcmResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
pub struct DeviceResult {
    pub device_id: Uuid,
    pub device_name: String,
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TestFcmAllResponse {
    pub sent: usize,
    pub skipped: usize,
    pub errors: usize,
    pub results: Vec<DeviceResult>,
}

#[derive(Debug, Deserialize, Default)]
pub struct TriggerUpdateBody {
    #[serde(default)]
    pub device_ids: Option<Vec<Uuid>>,
    #[serde(default)]
    pub version_code: Option<i32>,
    #[serde(default)]
    pub version_name: Option<String>,
    /// true: dev 端末だけ
    #[serde(default)]
    pub dev_only: Option<bool>,
    /// 指定時はアプリがこの URL から APK を取る
    #[serde(default)]
    pub download_url: Option<String>,
}

#[derive(Debug, Serialize, Default)]
pub struct TriggerUpdateResponse {
    pub sent: usize,
    pub skipped: usize,
    pub already_updated: usize,
    pub errors: usize,
    pub results: Vec<DeviceResult>,
}

// --- 口 ---

pub fn tenant_router() -> Router<AppState> {
    Router::new()
        .route("/devices/{id}/test-fcm", post(test_fcm))
        .route("/devices/test-fcm-all", post(test_fcm_all))
        .route("/devices/trigger-update", post(trigger_update))
}

pub fn public_router() -> Router<AppState> {
    Router::new()
        .route("/devices/fcm-notify-call", post(fcm_notify_call))
        .route("/devices/fcm-dismiss-test", post(fcm_dismiss_test))
        .route("/devices/test-fcm-all-exclude", post(test_fcm_all_exclude))
        .route("/devices/trigger-update-dev", post(trigger_update_dev))
}

async fn fcm_notify_call(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<FcmNotifyCallBody>,
) -> Result<Json<FcmNotifyCallResponse>, StatusCode> {
    check_internal_secret(state.internal_secret.as_deref(), &headers)?;
    let fcm = state.fcm_or_503()?;
    let mut resp = FcmNotifyCallResponse {
        sent: 0,
        skipped: 0,
        errors: 0,
    };
    if body.room_ids.is_empty() {
        return Ok(Json(resp));
    }
    let devices = {
        let mut pg = state.pg.lock().await;
        list_fcm_devices(&mut pg)
            .await
            .map_err(|e| state.db_fail("fcm notify call", &e))?
    };
    let exclude: HashSet<&str> = body.exclude_device_ids.iter().map(String::as_str).collect();
    let room_ids = Value::from(body.room_ids.clone()).to_string();
    for device in &devices {
        let now = (state.clock)();
        if exclude.contains(device.id.to_string().as_str())
            || !should_notify(device.call_enabled, device.call_schedule.as_ref(), now)
        {
            resp.skipped += 1;
            continue;
        }
        let mut d = data("incoming_call", Some(now));
        d.insert("room_ids".to_owned(), room_ids.clone());
        match fcm.send(&device.fcm_token, d).await {
            Ok(()) => resp.sent += 1,
            Err(_) => resp.errors += 1,
        }
    }
    (state.log)(&format!(
        "devices: fcm notify call sent={} skipped={} errors={}",
        resp.sent, resp.skipped, resp.errors
    ));
    Ok(Json(resp))
}

async fn fcm_dismiss_test(
    State(state): State<AppState>,
    Json(body): Json<FcmDismissTestBody>,
) -> Result<Json<Value>, StatusCode> {
    let fcm = state.fcm_or_503()?;
    let tokens = {
        let mut pg = state.pg.lock().await;
        dismiss_targets(&mut pg, body.device_id)
            .await
            .map_err(|e| state.db_fail("fcm dismiss test", &e))?
            .ok_or(StatusCode::NOT_FOUND)?
    };
    let mut sent = 0usize;
    for token in &tokens {
        if fcm.send(token, data("test_dismiss", None)).await.is_ok() {
            sent += 1;
        }
    }
    Ok(Json(json!({ "sent": sent })))
}

async fn test_fcm_all_exclude(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<TestFcmAllExcludeBody>,
) -> Result<Json<Value>, StatusCode> {
    check_internal_secret(state.internal_secret.as_deref(), &headers)?;
    let fcm = state.fcm_or_503()?;
    let rows = {
        let mut pg = state.pg.lock().await;
        list_all_callable(&mut pg)
            .await
            .map_err(|e| state.db_fail("test fcm all exclude", &e))?
    };
    let exclude: HashSet<&str> = body.exclude_device_ids.iter().map(String::as_str).collect();
    let (mut sent, mut errors) = (0usize, 0usize);
    let mut results = Vec::new();
    for device in rows
        .iter()
        .filter(|d| !exclude.contains(d.id.to_string().as_str()))
    {
        let d = data("test", Some((state.clock)()));
        match fcm.send(&device.fcm_token, d).await {
            Ok(()) => {
                sent += 1;
                results.push(json!({
                    "device_id": device.id.to_string(),
                    "device_name": device.device_name,
                    "success": true,
                }));
            }
            Err(e) => {
                errors += 1;
                results.push(json!({
                    "device_id": device.id.to_string(),
                    "device_name": device.device_name,
                    "success": false,
                    "error": e.to_string(),
                }));
            }
        }
    }
    Ok(Json(
        json!({ "sent": sent, "errors": errors, "results": results }),
    ))
}

async fn test_fcm(
    State(state): State<AppState>,
    Extension(TenantId(tenant_id)): Extension<TenantId>,
    Path(id): Path<Uuid>,
) -> Result<Json<TestFcmResponse>, StatusCode> {
    let fcm = state.fcm_or_503()?;
    let token = {
        let mut pg = state.pg.lock().await;
        device_fcm_token(&mut pg, tenant_id, id)
            .await
            .map_err(|e| state.db_fail("test fcm", &e))?
            .ok_or(StatusCode::NOT_FOUND)?
            .ok_or(StatusCode::BAD_REQUEST)?
    };
    let d = data("test", Some((state.clock)()));
    Ok(Json(match fcm.send(&token, d).await {
        Ok(()) => TestFcmResponse {
            success: true,
            error: None,
        },
        Err(e) => TestFcmResponse {
            success: false,
            error: Some(e.to_string()),
        },
    }))
}

/// 端末ごとに送って結果を返す (`test-fcm-all`・OTA で共有)
async fn send_each(
    fcm: &dyn FcmSend,
    device: &TargetDevice,
    d: Data,
    sent: &mut usize,
    errors: &mut usize,
) -> DeviceResult {
    let result = fcm.send(&device.fcm_token, d).await;
    if result.is_ok() {
        *sent += 1;
    } else {
        *errors += 1;
    }
    DeviceResult {
        device_id: device.id,
        device_name: device.device_name.clone(),
        success: result.is_ok(),
        error: result.err().map(|e| e.to_string()),
    }
}

async fn test_fcm_all(
    State(state): State<AppState>,
    Extension(TenantId(tenant_id)): Extension<TenantId>,
) -> Result<Json<TestFcmAllResponse>, StatusCode> {
    let fcm = state.fcm_or_503()?;
    let rows = {
        let mut pg = state.pg.lock().await;
        tenant_fcm_devices(&mut pg, tenant_id)
            .await
            .map_err(|e| state.db_fail("test fcm all", &e))?
    };
    let (mut sent, mut errors) = (0usize, 0usize);
    let mut results = Vec::new();
    for device in &rows {
        let d = data("test", Some((state.clock)()));
        results.push(send_each(fcm, device, d, &mut sent, &mut errors).await);
    }
    Ok(Json(TestFcmAllResponse {
        sent,
        skipped: 0,
        errors,
        results,
    }))
}

/// OTA の共通の処理 (rust の `send_update_fcm`)
async fn send_update(
    state: &AppState,
    tenant_id: Uuid,
    body: &TriggerUpdateBody,
    dev_only: bool,
) -> Result<TriggerUpdateResponse, StatusCode> {
    let fcm = state.fcm_or_503()?;
    let rows = {
        let mut pg = state.pg.lock().await;
        ota_devices(&mut pg, tenant_id, dev_only)
            .await
            .map_err(|e| state.db_fail("trigger update", &e))?
    };
    let filter: Option<HashSet<Uuid>> = body
        .device_ids
        .as_ref()
        .map(|ids| ids.iter().copied().collect());
    let mut resp = TriggerUpdateResponse::default();
    for device in &rows {
        if filter.as_ref().is_some_and(|f| !f.contains(&device.id)) {
            resp.skipped += 1;
            continue;
        }
        if let (Some(target), Some(current)) = (body.version_code, device.app_version_code) {
            if current >= target {
                resp.already_updated += 1;
                resp.results.push(DeviceResult {
                    device_id: device.id,
                    device_name: device.device_name.clone(),
                    success: true,
                    error: Some("already up-to-date".to_owned()),
                });
                continue;
            }
        }
        let mut d = data("app_update", Some((state.clock)()));
        if let Some(vc) = body.version_code {
            d.insert("version_code".to_owned(), vc.to_string());
        }
        if let Some(vn) = &body.version_name {
            d.insert("version_name".to_owned(), vn.clone());
        }
        if let Some(url) = &body.download_url {
            d.insert("download_url".to_owned(), url.clone());
        }
        let r = send_each(fcm, device, d, &mut resp.sent, &mut resp.errors).await;
        resp.results.push(r);
    }
    Ok(resp)
}

async fn trigger_update(
    State(state): State<AppState>,
    Extension(TenantId(tenant_id)): Extension<TenantId>,
    Json(body): Json<TriggerUpdateBody>,
) -> Result<Json<TriggerUpdateResponse>, StatusCode> {
    let dev_only = body.dev_only.unwrap_or(false);
    send_update(&state, tenant_id, &body, dev_only)
        .await
        .map(Json)
}

async fn trigger_update_dev(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<TriggerUpdateBody>,
) -> Result<Json<TriggerUpdateResponse>, StatusCode> {
    check_internal_secret(state.internal_secret.as_deref(), &headers)?;
    let tenants = {
        let mut pg = state.pg.lock().await;
        list_dev_tenants(&mut pg)
            .await
            .map_err(|e| state.db_fail("trigger update dev", &e))?
    };
    // テナントごとの失敗 (FCM が無い・DB) は飛ばして合算する (rust と同じ)
    let mut total = TriggerUpdateResponse::default();
    for tenant_id in tenants {
        if let Ok(resp) = send_update(&state, tenant_id, &body, true).await {
            total.sent += resp.sent;
            total.skipped += resp.skipped;
            total.already_updated += resp.already_updated;
            total.errors += resp.errors;
            total.results.extend(resp.results);
        }
    }
    Ok(Json(total))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 2026-10-28 (水) 10:30 JST = 01:30 UTC
    const WED_1030_JST: i64 = 1_793_151_000_000;

    #[test]
    fn schedule_matches_rust() {
        assert!(!should_notify(false, None, WED_1030_JST));
        assert!(should_notify(true, None, WED_1030_JST));
        let s = |v: Value| should_notify(true, Some(&v), WED_1030_JST);
        assert!(!s(json!({ "enabled": false })));
        assert!(s(json!({ "enabled": true })));
        // 水 = 3
        assert!(s(json!({ "days": [1, 2, 3] })));
        assert!(!s(json!({ "days": [0, 6] })));
        assert!(s(json!({ "days": [] })));
        assert!(s(json!({ "startHour": 9, "endHour": 17 })));
        assert!(!s(json!({ "startHour": 11, "endHour": 17 })));
        assert!(!s(json!({ "startHour": 9, "endHour": 10, "endMin": 30 })));
        assert!(s(json!({ "startHour": 10, "startMin": 30, "endHour": 11 })));
        // 日をまたぐ範囲
        assert!(s(json!({ "startHour": 22, "endHour": 11 })));
        assert!(!s(json!({ "startHour": 22, "endHour": 6 })));
    }

    #[test]
    fn internal_secret_is_fail_closed() {
        let mut h = HeaderMap::new();
        assert_eq!(
            check_internal_secret(None, &h),
            Err(StatusCode::SERVICE_UNAVAILABLE)
        );
        assert_eq!(
            check_internal_secret(Some("s3"), &h),
            Err(StatusCode::UNAUTHORIZED)
        );
        h.insert("X-Internal-Secret", "s3".parse().unwrap());
        assert_eq!(check_internal_secret(Some("s3"), &h), Ok(()));
        assert_eq!(
            check_internal_secret(Some("other"), &h),
            Err(StatusCode::UNAUTHORIZED)
        );
    }
}
