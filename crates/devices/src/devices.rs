//! 端末の登録・管理 (rust の `alc-devices` の devices.rs・repo/devices.rs の写し)。
//!
//! 管理画面の口 (`X-Tenant-ID` 必須):
//! - `GET /devices` — 端末の一覧 (作成の新しい順)。`GET /devices/pending` — 承認待ちの登録 (自分のテナントとテナント未定、期限内)
//! - `POST /devices/register/create-token` (URL・24 時間)・`create-permanent-qr` (QR 永久)・`create-device-owner-token` — 登録用のコードの発行
//! - `POST /devices/approve/{id}`・`POST /devices/approve-by-code/{code}` — 承認 (端末の行を作り、登録を approved に)
//! - `POST /devices/reject/{id}`・`disable/{id}`・`enable/{id}`・`DELETE /devices/{id}` (204。無ければ 404)
//! - `PUT /devices/{id}/call-settings` (204) — 着信の設定
//!
//! 端末の口 (rust では公開。テナントは端末の ID から引く):
//! - `POST /devices/register/request` — QR 一時の登録の申請 (10 分)。`GET /devices/register/status/{code}` — その状態
//! - `POST /devices/register/claim` — URL・Device Owner は即登録、QR 永久は承認待ち
//! - `GET /devices/settings/{device_id}` — 端末の設定 (`X-Device-Token` を照合)
//! - `PUT /devices/register-fcm-token`・`update-last-login`・`report-version`・`report-watchdog` (204)
//!
//! 内部の口: `GET /internal/devices/{device_id}/pairing-tenant` — 有効な端末のテナント (auth-worker の device credential 発行)
//!
//! rust との違い:
//! - 登録のコードと settings_token (UUID v4) は DB が作る (`gen_random_uuid()`)。QR 一時のコードの衝突の確かめ
//!   (rust の `code_exists` の繰り返し) は持たない (122 bit の乱数で、表の UNIQUE が最後の守り)
//! - 端末の表の文に tenant_id を明示した (rust は RLS 任せ)。承認の対象の登録は、承認者のテナントかテナント未定のものだけ引く
//!   (rust は ID で引いて、更新の RLS で他テナントの登録を書き換えられないだけだった)
//! - 着信の設定で always_on・bp_enabled が変わったときの FCM の通知 (`settings_changed`) はまだ送らない (W6b-c で FCM を足す)
//! - ログに端末の ID・コード・社員の名前を出さない (固定の語だけ)

use alc_core_wasm::{AuthUser, TenantId};
use alc_worker_db::{PgClient, TenantTx, TxOutput};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{delete, get, post, put};
use axum::{Extension, Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio_postgres::types::{ToSql, Type};
use tokio_postgres::{Error, Row};
use uuid::Uuid;

use crate::AppState;

type Param<'a> = (&'a (dyn ToSql + Sync), Type);

pub mod sql {
    /// 端末の一覧 (作成の新しい順)。列は rust の `DeviceRow` の並び (時刻は rust と同じく text)。$1 tenant_id
    pub const LIST_DEVICES: &str =
        "SELECT id, tenant_id, device_name, device_type, phone_number, user_id, status, \
                approved_by, approved_at::text, last_seen_at::text, \
                call_enabled, call_schedule, fcm_token, \
                last_login_employee_id, last_login_employee_name, last_login_employee_role, \
                app_version_code, app_version_name, is_device_owner, is_dev_device, \
                always_on, watchdog_running, created_at::text, updated_at::text, \
                re_pair_authorized_until::text, last_re_pair_at::text, re_pair_count, hardware_id, \
                bp_enabled \
           FROM alc_api.devices WHERE tenant_id = $1 ORDER BY created_at DESC";

    /// 承認待ち (自分のテナントとテナント未定、期限内)。$1 tenant_id
    pub const LIST_PENDING: &str = "SELECT id, registration_code, flow_type, tenant_id, phone_number, device_name, \
                status, device_id, expires_at::text, is_device_owner, is_dev_device, created_at::text \
           FROM alc_api.device_registration_requests \
          WHERE status = 'pending' \
            AND (tenant_id = $1 OR tenant_id IS NULL) \
            AND (expires_at IS NULL OR expires_at > NOW()) \
          ORDER BY created_at DESC";

    /// URL の登録 (24 時間)。$1 tenant_id / $2 端末名 / $3 Device Owner / $4 開発端末 → コード
    pub const CREATE_URL_TOKEN: &str = "INSERT INTO alc_api.device_registration_requests \
         (registration_code, flow_type, tenant_id, device_name, status, expires_at, is_device_owner, is_dev_device) \
         VALUES (gen_random_uuid()::text, 'url', $1, $2, 'pending', NOW() + INTERVAL '24 hours', $3, $4) \
         RETURNING registration_code";

    /// Device Owner の登録 (期限なし)。$1 tenant_id / $2 端末名 / $3 開発端末 → コード
    pub const CREATE_DEVICE_OWNER_TOKEN: &str = "INSERT INTO alc_api.device_registration_requests \
         (registration_code, flow_type, tenant_id, device_name, status, is_device_owner, is_dev_device) \
         VALUES (gen_random_uuid()::text, 'device_owner', $1, $2, 'pending', true, $3) \
         RETURNING registration_code";

    /// QR 永久の登録 (期限なし)。$1 tenant_id / $2 端末名 / $3 Device Owner / $4 開発端末 → コード
    pub const CREATE_PERMANENT_QR: &str = "INSERT INTO alc_api.device_registration_requests \
         (registration_code, flow_type, tenant_id, device_name, status, is_device_owner, is_dev_device) \
         VALUES (gen_random_uuid()::text, 'qr_permanent', $1, $2, 'pending', $3, $4) \
         RETURNING registration_code";

    /// 承認の対象 (承認待ち、承認者のテナントかテナント未定)。$1 tenant_id / $2 id
    pub const FIND_APPROVE: &str =
        "SELECT id, phone_number, device_name, is_device_owner, is_dev_device \
           FROM alc_api.device_registration_requests \
          WHERE id = $2 AND status = 'pending' AND (tenant_id = $1 OR tenant_id IS NULL)";

    /// コードでの承認の対象 (承認待ち・期限内、承認者のテナントかテナント未定)。$1 tenant_id / $2 コード
    pub const FIND_APPROVE_BY_CODE: &str =
        "SELECT id, phone_number, device_name, is_device_owner, is_dev_device \
           FROM alc_api.device_registration_requests \
          WHERE registration_code = $2 AND status = 'pending' \
            AND (expires_at IS NULL OR expires_at > NOW()) \
            AND (tenant_id = $1 OR tenant_id IS NULL)";

    /// 承認した端末を作る。$1 tenant_id / $2 端末名 / $3 種類 / $4 電話番号 / $5 承認者 / $6 Device Owner / $7 開発端末 → id
    pub const INSERT_APPROVED_DEVICE: &str = "INSERT INTO alc_api.devices \
         (tenant_id, device_name, device_type, phone_number, status, approved_by, approved_at, is_device_owner, is_dev_device, settings_token) \
         VALUES ($1, $2, $3, $4, 'active', $5, NOW(), $6, $7, gen_random_uuid()) \
         RETURNING id";

    /// 登録を approved にする (テナント未定なら承認者のテナントに)。$1 device_id / $2 tenant_id / $3 id
    pub const MARK_APPROVED: &str = "UPDATE alc_api.device_registration_requests \
            SET status = 'approved', device_id = $1, tenant_id = COALESCE(tenant_id, $2) \
          WHERE id = $3";

    /// 却下 (承認待ちだけ。自分のテナントかテナント未定)。$1 tenant_id / $2 id
    pub const REJECT: &str = "UPDATE alc_api.device_registration_requests SET status = 'rejected' \
          WHERE id = $2 AND status = 'pending' AND (tenant_id = $1 OR tenant_id IS NULL)";

    /// 停止 (有効なものだけ)。$1 tenant_id / $2 id
    pub const DISABLE: &str = "UPDATE alc_api.devices SET status = 'disabled', updated_at = NOW() \
          WHERE tenant_id = $1 AND id = $2 AND status = 'active'";

    /// 再開 (停止中のものだけ)。$1 tenant_id / $2 id
    pub const ENABLE: &str = "UPDATE alc_api.devices SET status = 'active', updated_at = NOW() \
          WHERE tenant_id = $1 AND id = $2 AND status = 'disabled'";

    /// 削除。$1 tenant_id / $2 id
    pub const DELETE: &str = "DELETE FROM alc_api.devices WHERE tenant_id = $1 AND id = $2";

    /// 着信の設定 (always_on・bp_enabled は NULL なら変えない)。$1 tenant_id / $2 id / $3 call_enabled / $4 call_schedule /
    /// $5 always_on / $6 bp_enabled
    pub const UPDATE_CALL_SETTINGS: &str = "UPDATE alc_api.devices \
            SET call_enabled = $3, call_schedule = $4, always_on = COALESCE($5, always_on), \
                bp_enabled = COALESCE($6, bp_enabled), updated_at = NOW() \
          WHERE tenant_id = $1 AND id = $2";

    // ---- 端末の口 (テナントの決まる前の文は SECURITY DEFINER の関数か、USING (true) の登録の表だけ) ----

    /// QR 一時の登録の申請 (10 分)。$1 端末名 → コード・期限
    pub const CREATE_REGISTRATION_REQUEST: &str =
        "INSERT INTO alc_api.device_registration_requests \
         (registration_code, flow_type, device_name, status, expires_at) \
         VALUES (gen_random_uuid()::text, 'qr_temp', $1, 'pending', NOW() + INTERVAL '10 minutes') \
         RETURNING registration_code, expires_at::text";

    /// 登録の状態 (期限切れかどうかも)。$1 コード
    pub const REGISTRATION_STATUS: &str = "SELECT status, device_id, tenant_id, \
                (expires_at IS NOT NULL AND expires_at < NOW()) AS expired, NULLIF(device_name, '') \
           FROM alc_api.device_registration_requests WHERE registration_code = $1";

    /// 端末の状態 (テナント・有効か・settings_token)。$1 device_id
    pub const RE_PAIR_STATE: &str =
        "SELECT tenant_id, status, settings_token FROM alc_api.get_device_re_pair_state($1)";

    /// 受け取りの対象。$1 コード
    pub const FIND_CLAIM: &str =
        "SELECT id, flow_type, tenant_id, status, device_name, is_device_owner, is_dev_device \
           FROM alc_api.device_registration_requests WHERE registration_code = $1";

    /// URL・Device Owner の受け取りで端末を作る。$1 tenant_id / $2 端末名 / $3 電話番号 / $4 Device Owner / $5 開発端末
    /// → id・settings_token
    pub const INSERT_CLAIMED_DEVICE: &str = "INSERT INTO alc_api.devices \
         (tenant_id, device_name, device_type, phone_number, status, approved_at, is_device_owner, is_dev_device, settings_token) \
         VALUES ($1, $2, 'android', $3, 'active', NOW(), $4, $5, gen_random_uuid()) \
         RETURNING id, settings_token";

    /// 受け取った登録を approved にする。$1 device_id / $2 電話番号 / $3 端末名 / $4 id
    pub const MARK_CLAIMED: &str = "UPDATE alc_api.device_registration_requests \
            SET status = 'approved', device_id = $1, phone_number = $2, device_name = $3 \
          WHERE id = $4";

    /// QR 永久の受け取り (承認待ちのまま電話番号と端末名を入れる)。$1 tenant_id / $2 id / $3 電話番号 / $4 端末名
    pub const CLAIM_PERMANENT_QR: &str = "UPDATE alc_api.device_registration_requests \
            SET phone_number = $3, device_name = $4 \
          WHERE id = $2 AND tenant_id = $1";

    /// 端末の設定 (SECURITY DEFINER)。$1 device_id
    pub const DEVICE_SETTINGS: &str = "SELECT call_enabled, call_schedule, status, last_login_employee_id, \
                last_login_employee_name, last_login_employee_role, always_on, settings_token, bp_enabled \
           FROM alc_api.get_device_settings_by_id($1)";

    /// 端末のテナント (SECURITY DEFINER。端末が無ければ NULL)。$1 device_id
    pub const LOOKUP_TENANT: &str = "SELECT alc_api.lookup_device_tenant($1)";

    /// FCM token。$1 tenant_id / $2 device_id / $3 token
    pub const UPDATE_FCM_TOKEN: &str =
        "UPDATE alc_api.devices SET fcm_token = $3, updated_at = NOW() WHERE tenant_id = $1 AND id = $2";

    /// 最終ログイン。$1 tenant_id / $2 device_id / $3 社員 / $4 名前 / $5 役割
    pub const UPDATE_LAST_LOGIN: &str = "UPDATE alc_api.devices \
            SET last_login_employee_id = $3, last_login_employee_name = $4, last_login_employee_role = $5, \
                updated_at = NOW() \
          WHERE tenant_id = $1 AND id = $2";

    /// watchdog の状態。$1 tenant_id / $2 device_id / $3 running
    pub const UPDATE_WATCHDOG: &str =
        "UPDATE alc_api.devices SET watchdog_running = $3, updated_at = NOW() WHERE tenant_id = $1 AND id = $2";

    /// 版の報告。$1 tenant_id / $2 device_id / $3 version_code / $4 version_name / $5 Device Owner / $6 開発端末
    pub const REPORT_VERSION: &str = "UPDATE alc_api.devices \
            SET app_version_code = $3, app_version_name = $4, is_device_owner = $5, is_dev_device = $6, \
                app_version_reported_at = NOW(), updated_at = NOW() \
          WHERE tenant_id = $1 AND id = $2";
}

// --- 行と本文 (rust の型の写し。JSON の形は同じ) ---

/// rust の `Device`
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Device {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub device_name: String,
    pub device_type: String,
    pub phone_number: Option<String>,
    pub user_id: Option<Uuid>,
    pub status: String,
    pub approved_by: Option<Uuid>,
    pub approved_at: Option<String>,
    pub last_seen_at: Option<String>,
    pub call_enabled: bool,
    pub call_schedule: Option<Value>,
    pub fcm_token: Option<String>,
    pub last_login_employee_id: Option<Uuid>,
    pub last_login_employee_name: Option<String>,
    pub last_login_employee_role: Option<Vec<String>>,
    pub app_version_code: Option<i32>,
    pub app_version_name: Option<String>,
    pub is_device_owner: bool,
    pub is_dev_device: bool,
    pub always_on: bool,
    pub watchdog_running: Option<bool>,
    pub created_at: String,
    pub updated_at: String,
    pub re_pair_authorized_until: Option<String>,
    pub last_re_pair_at: Option<String>,
    pub re_pair_count: i32,
    pub hardware_id: Option<String>,
    pub bp_enabled: bool,
}

impl TxOutput for Device {}

fn device(r: &Row) -> Device {
    Device {
        id: r.get(0),
        tenant_id: r.get(1),
        device_name: r.get(2),
        device_type: r.get(3),
        phone_number: r.get(4),
        user_id: r.get(5),
        status: r.get(6),
        approved_by: r.get(7),
        approved_at: r.get(8),
        last_seen_at: r.get(9),
        call_enabled: r.get(10),
        call_schedule: r.get(11),
        fcm_token: r.get(12),
        last_login_employee_id: r.get(13),
        last_login_employee_name: r.get(14),
        last_login_employee_role: r.get(15),
        app_version_code: r.get(16),
        app_version_name: r.get(17),
        is_device_owner: r.get(18),
        is_dev_device: r.get(19),
        always_on: r.get(20),
        watchdog_running: r.get(21),
        created_at: r.get(22),
        updated_at: r.get(23),
        re_pair_authorized_until: r.get(24),
        last_re_pair_at: r.get(25),
        re_pair_count: r.get(26),
        hardware_id: r.get(27),
        bp_enabled: r.get(28),
    }
}

/// rust の `RegistrationRequest`
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RegistrationRequest {
    pub id: Uuid,
    pub registration_code: String,
    pub flow_type: String,
    pub tenant_id: Option<Uuid>,
    pub phone_number: Option<String>,
    pub device_name: String,
    pub status: String,
    pub device_id: Option<Uuid>,
    pub expires_at: Option<String>,
    pub is_device_owner: bool,
    pub is_dev_device: bool,
    pub created_at: String,
}

impl TxOutput for RegistrationRequest {}

fn registration_request(r: &Row) -> RegistrationRequest {
    RegistrationRequest {
        id: r.get(0),
        registration_code: r.get(1),
        flow_type: r.get(2),
        tenant_id: r.get(3),
        phone_number: r.get(4),
        device_name: r.get(5),
        status: r.get(6),
        device_id: r.get(7),
        expires_at: r.get(8),
        is_device_owner: r.get(9),
        is_dev_device: r.get(10),
        created_at: r.get(11),
    }
}

/// 承認の対象 (rust の `ApproveLookupRow` の使う列だけ)
#[derive(Debug, Clone, PartialEq)]
pub struct ApproveTarget {
    pub id: Uuid,
    pub phone_number: Option<String>,
    pub device_name: String,
    pub is_device_owner: bool,
    pub is_dev_device: bool,
}

impl TxOutput for ApproveTarget {}

/// 端末を作るときの値
#[derive(Debug, Clone)]
pub struct NewDevice {
    pub device_name: String,
    pub phone_number: Option<String>,
    pub approved_by: Option<Uuid>,
    pub is_device_owner: bool,
    pub is_dev_device: bool,
}

impl NewDevice {
    /// 電話番号があれば android、無ければ kiosk (rust と同じ)
    pub fn device_type(&self) -> &'static str {
        if self.phone_number.is_some() {
            "android"
        } else {
            "kiosk"
        }
    }
}

/// 登録の状態 (rust の `RegistrationStatusRow`。期限切れは DB で判定)
#[derive(Debug, Clone, PartialEq)]
pub struct RegistrationStatus {
    pub status: String,
    pub device_id: Option<Uuid>,
    pub tenant_id: Option<Uuid>,
    pub expired: bool,
    pub device_name: Option<String>,
    pub settings_token: Option<Uuid>,
}

impl TxOutput for RegistrationStatus {}

/// 受け取りの対象 (rust の `ClaimLookupRow` の使う列)
#[derive(Debug, Clone, PartialEq)]
pub struct ClaimTarget {
    pub id: Uuid,
    pub flow_type: String,
    pub tenant_id: Option<Uuid>,
    pub status: String,
    pub device_name: String,
    pub is_device_owner: bool,
    pub is_dev_device: bool,
}

impl TxOutput for ClaimTarget {}

/// 端末の設定 (rust の `DeviceSettingsRow`)
#[derive(Debug, Clone, PartialEq)]
pub struct DeviceSettings {
    pub call_enabled: bool,
    pub call_schedule: Option<Value>,
    pub status: String,
    pub last_login_employee_id: Option<Uuid>,
    pub last_login_employee_name: Option<String>,
    pub last_login_employee_role: Option<Vec<String>>,
    pub always_on: bool,
    pub settings_token: Option<Uuid>,
    pub bp_enabled: bool,
}

impl TxOutput for DeviceSettings {}

// --- DB ---

/// 端末の一覧
pub async fn list_devices(pg: &mut PgClient, tenant_id: Uuid) -> Result<Vec<Device>, Error> {
    pg.tenant_tx(tenant_id, move |tx| {
        Box::pin(async move {
            let rows = tx
                .query_typed(sql::LIST_DEVICES, &[(&tenant_id, Type::UUID)])
                .await?;
            Ok(rows.iter().map(device).collect())
        })
    })
    .await
}

/// 承認待ち
pub async fn list_pending(
    pg: &mut PgClient,
    tenant_id: Uuid,
) -> Result<Vec<RegistrationRequest>, Error> {
    pg.tenant_tx(tenant_id, move |tx| {
        Box::pin(async move {
            let rows = tx
                .query_typed(sql::LIST_PENDING, &[(&tenant_id, Type::UUID)])
                .await?;
            Ok(rows.iter().map(registration_request).collect())
        })
    })
    .await
}

/// 登録用のコードの発行の種類
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenKind {
    Url,
    DeviceOwner,
    PermanentQr,
}

/// 登録用のコードを発行する (DB が UUID v4 を作る)
pub async fn create_token(
    pg: &mut PgClient,
    tenant_id: Uuid,
    kind: TokenKind,
    device_name: String,
    is_device_owner: bool,
    is_dev_device: bool,
) -> Result<String, Error> {
    pg.tenant_tx(tenant_id, move |tx| {
        Box::pin(async move {
            let row = match kind {
                TokenKind::Url => {
                    let p: [Param; 4] = [
                        (&tenant_id, Type::UUID),
                        (&device_name, Type::TEXT),
                        (&is_device_owner, Type::BOOL),
                        (&is_dev_device, Type::BOOL),
                    ];
                    tx.query_typed_one(sql::CREATE_URL_TOKEN, &p).await?
                }
                TokenKind::DeviceOwner => {
                    let p: [Param; 3] = [
                        (&tenant_id, Type::UUID),
                        (&device_name, Type::TEXT),
                        (&is_dev_device, Type::BOOL),
                    ];
                    tx.query_typed_one(sql::CREATE_DEVICE_OWNER_TOKEN, &p)
                        .await?
                }
                TokenKind::PermanentQr => {
                    let p: [Param; 4] = [
                        (&tenant_id, Type::UUID),
                        (&device_name, Type::TEXT),
                        (&is_device_owner, Type::BOOL),
                        (&is_dev_device, Type::BOOL),
                    ];
                    tx.query_typed_one(sql::CREATE_PERMANENT_QR, &p).await?
                }
            };
            Ok(row.get::<_, String>(0))
        })
    })
    .await
}

/// 承認の対象を引く (`by_code` ならコードで、そうでなければ ID で)
pub async fn find_approve_target(
    pg: &mut PgClient,
    tenant_id: Uuid,
    key: ApproveKey,
) -> Result<Option<ApproveTarget>, Error> {
    pg.tenant_tx(tenant_id, move |tx| {
        Box::pin(async move {
            let row = match &key {
                ApproveKey::Id(id) => {
                    tx.query_typed_opt(
                        sql::FIND_APPROVE,
                        &[(&tenant_id, Type::UUID), (id, Type::UUID)],
                    )
                    .await?
                }
                ApproveKey::Code(code) => {
                    tx.query_typed_opt(
                        sql::FIND_APPROVE_BY_CODE,
                        &[(&tenant_id, Type::UUID), (code, Type::TEXT)],
                    )
                    .await?
                }
            };
            Ok(row.map(|r| ApproveTarget {
                id: r.get(0),
                phone_number: r.get(1),
                device_name: r.get(2),
                is_device_owner: r.get(3),
                is_dev_device: r.get(4),
            }))
        })
    })
    .await
}

/// 承認の対象の引き方
#[derive(Debug, Clone)]
pub enum ApproveKey {
    Id(Uuid),
    Code(String),
}

/// 承認する (端末を作り、登録を approved にする。1 つの transaction)。端末の ID を返す
pub async fn approve(
    pg: &mut PgClient,
    tenant_id: Uuid,
    req_id: Uuid,
    new: NewDevice,
) -> Result<Uuid, Error> {
    pg.tenant_tx(tenant_id, move |tx| {
        Box::pin(async move {
            let device_type = new.device_type();
            let p: [Param; 7] = [
                (&tenant_id, Type::UUID),
                (&new.device_name, Type::TEXT),
                (&device_type, Type::TEXT),
                (&new.phone_number, Type::TEXT),
                (&new.approved_by, Type::UUID),
                (&new.is_device_owner, Type::BOOL),
                (&new.is_dev_device, Type::BOOL),
            ];
            let device_id: Uuid = tx
                .query_typed_one(sql::INSERT_APPROVED_DEVICE, &p)
                .await?
                .get(0);
            tx.execute_typed(
                sql::MARK_APPROVED,
                &[
                    (&device_id, Type::UUID),
                    (&tenant_id, Type::UUID),
                    (&req_id, Type::UUID),
                ],
            )
            .await?;
            Ok(device_id)
        })
    })
    .await
}

/// `(tenant_id, id)` だけを取る更新・削除の文を流し、行が在ったかを返す
pub async fn exec_by_id(
    pg: &mut PgClient,
    tenant_id: Uuid,
    statement: &'static str,
    id: Uuid,
) -> Result<bool, Error> {
    pg.tenant_tx(tenant_id, move |tx| {
        Box::pin(async move {
            let n = tx
                .execute_typed(statement, &[(&tenant_id, Type::UUID), (&id, Type::UUID)])
                .await?;
            Ok(n > 0)
        })
    })
    .await
}

/// 着信の設定。行が在ったかを返す
pub async fn update_call_settings(
    pg: &mut PgClient,
    tenant_id: Uuid,
    id: Uuid,
    body: UpdateCallSettingsBody,
) -> Result<bool, Error> {
    pg.tenant_tx(tenant_id, move |tx| {
        Box::pin(async move {
            let p: [Param; 6] = [
                (&tenant_id, Type::UUID),
                (&id, Type::UUID),
                (&body.call_enabled, Type::BOOL),
                (&body.call_schedule, Type::JSONB),
                (&body.always_on, Type::BOOL),
                (&body.bp_enabled, Type::BOOL),
            ];
            Ok(tx.execute_typed(sql::UPDATE_CALL_SETTINGS, &p).await? > 0)
        })
    })
    .await
}

/// QR 一時の登録の申請。コードと期限を返す
pub async fn create_registration_request(
    pg: &mut PgClient,
    device_name: String,
) -> Result<(String, String), Error> {
    pg.tenant_tx(Uuid::nil(), move |tx| {
        Box::pin(async move {
            let row = tx
                .query_typed_one(
                    sql::CREATE_REGISTRATION_REQUEST,
                    &[(&device_name, Type::TEXT)],
                )
                .await?;
            Ok((row.get(0), row.get(1)))
        })
    })
    .await
}

/// 端末の状態 (テナント・状態・settings_token)。テナントに依らない関数なので、どの transaction で流してもよい
async fn re_pair_state(
    tx: &TenantTx<'_>,
    device_id: Uuid,
) -> Result<Option<(Uuid, String, Option<Uuid>)>, Error> {
    Ok(tx
        .query_typed_opt(sql::RE_PAIR_STATE, &[(&device_id, Type::UUID)])
        .await?
        .map(|r| (r.get(0), r.get(1), r.get(2))))
}

/// 登録の状態
pub async fn registration_status(
    pg: &mut PgClient,
    code: String,
) -> Result<Option<RegistrationStatus>, Error> {
    pg.tenant_tx(Uuid::nil(), move |tx| {
        Box::pin(async move {
            let Some(r) = tx
                .query_typed_opt(sql::REGISTRATION_STATUS, &[(&code, Type::TEXT)])
                .await?
            else {
                return Ok(None);
            };
            let device_id: Option<Uuid> = r.get(1);
            let settings_token = match device_id {
                Some(id) => re_pair_state(tx, id).await?.and_then(|s| s.2),
                None => None,
            };
            Ok(Some(RegistrationStatus {
                status: r.get(0),
                device_id,
                tenant_id: r.get(2),
                expired: r.get(3),
                device_name: r.get(4),
                settings_token,
            }))
        })
    })
    .await
}

/// 受け取りの対象
pub async fn find_claim(pg: &mut PgClient, code: String) -> Result<Option<ClaimTarget>, Error> {
    pg.tenant_tx(Uuid::nil(), move |tx| {
        Box::pin(async move {
            Ok(tx
                .query_typed_opt(sql::FIND_CLAIM, &[(&code, Type::TEXT)])
                .await?
                .map(|r| ClaimTarget {
                    id: r.get(0),
                    flow_type: r.get(1),
                    tenant_id: r.get(2),
                    status: r.get(3),
                    device_name: r.get(4),
                    is_device_owner: r.get(5),
                    is_dev_device: r.get(6),
                }))
        })
    })
    .await
}

/// URL・Device Owner の受け取り (端末を作り、登録を approved にする)。端末の ID と settings_token を返す
pub async fn claim_device(
    pg: &mut PgClient,
    tenant_id: Uuid,
    req_id: Uuid,
    new: NewDevice,
) -> Result<(Uuid, Uuid), Error> {
    pg.tenant_tx(tenant_id, move |tx| {
        Box::pin(async move {
            let p: [Param; 5] = [
                (&tenant_id, Type::UUID),
                (&new.device_name, Type::TEXT),
                (&new.phone_number, Type::TEXT),
                (&new.is_device_owner, Type::BOOL),
                (&new.is_dev_device, Type::BOOL),
            ];
            let row = tx.query_typed_one(sql::INSERT_CLAIMED_DEVICE, &p).await?;
            let (device_id, token): (Uuid, Uuid) = (row.get(0), row.get(1));
            tx.execute_typed(
                sql::MARK_CLAIMED,
                &[
                    (&device_id, Type::UUID),
                    (&new.phone_number, Type::TEXT),
                    (&new.device_name, Type::TEXT),
                    (&req_id, Type::UUID),
                ],
            )
            .await?;
            Ok((device_id, token))
        })
    })
    .await
}

/// QR 永久の受け取り (承認待ちのまま)
pub async fn claim_permanent_qr(
    pg: &mut PgClient,
    tenant_id: Uuid,
    req_id: Uuid,
    phone_number: Option<String>,
    device_name: String,
) -> Result<(), Error> {
    pg.tenant_tx(tenant_id, move |tx| {
        Box::pin(async move {
            let p: [Param; 4] = [
                (&tenant_id, Type::UUID),
                (&req_id, Type::UUID),
                (&phone_number, Type::TEXT),
                (&device_name, Type::TEXT),
            ];
            tx.execute_typed(sql::CLAIM_PERMANENT_QR, &p).await?;
            Ok(())
        })
    })
    .await
}

/// 端末の設定
pub async fn device_settings(
    pg: &mut PgClient,
    device_id: Uuid,
) -> Result<Option<DeviceSettings>, Error> {
    pg.tenant_tx(Uuid::nil(), move |tx| {
        Box::pin(async move {
            Ok(tx
                .query_typed_opt(sql::DEVICE_SETTINGS, &[(&device_id, Type::UUID)])
                .await?
                .map(|r| DeviceSettings {
                    call_enabled: r.get(0),
                    call_schedule: r.get(1),
                    status: r.get(2),
                    last_login_employee_id: r.get(3),
                    last_login_employee_name: r.get(4),
                    last_login_employee_role: r.get(5),
                    always_on: r.get(6),
                    settings_token: r.get(7),
                    bp_enabled: r.get(8),
                }))
        })
    })
    .await
}

/// 有効な端末のテナント (auth-worker の device credential 発行)
pub async fn pairing_tenant(pg: &mut PgClient, device_id: Uuid) -> Result<Option<Uuid>, Error> {
    pg.tenant_tx(Uuid::nil(), move |tx| {
        Box::pin(async move {
            Ok(re_pair_state(tx, device_id)
                .await?
                .filter(|(_, status, _)| status == "active")
                .map(|(tenant_id, _, _)| tenant_id))
        })
    })
    .await
}

/// 端末からの更新 (テナントは端末の ID から引く)
#[derive(Debug, Clone)]
pub enum DeviceReport {
    FcmToken(String),
    LastLogin {
        employee_id: Uuid,
        name: String,
        role: Vec<String>,
    },
    Watchdog(bool),
    Version {
        code: i32,
        name: String,
        is_device_owner: bool,
        is_dev_device: bool,
    },
}

/// 端末のテナントを引き、そのテナントで端末の行を更新する。端末が無ければ `Ok(false)`
pub async fn report(
    pg: &mut PgClient,
    device_id: Uuid,
    report: DeviceReport,
) -> Result<bool, Error> {
    let tenant: Option<Uuid> = pg
        .tenant_tx(Uuid::nil(), move |tx| {
            Box::pin(async move {
                Ok(tx
                    .query_typed_opt(sql::LOOKUP_TENANT, &[(&device_id, Type::UUID)])
                    .await?
                    .and_then(|r| r.get(0)))
            })
        })
        .await?;
    let Some(tenant_id) = tenant else {
        return Ok(false);
    };
    pg.tenant_tx(tenant_id, move |tx| {
        Box::pin(async move {
            let (t, d) = (&tenant_id, &device_id);
            match &report {
                DeviceReport::FcmToken(token) => {
                    let p: [Param; 3] = [(t, Type::UUID), (d, Type::UUID), (token, Type::TEXT)];
                    tx.execute_typed(sql::UPDATE_FCM_TOKEN, &p).await?
                }
                DeviceReport::LastLogin {
                    employee_id,
                    name,
                    role,
                } => {
                    let p: [Param; 5] = [
                        (t, Type::UUID),
                        (d, Type::UUID),
                        (employee_id, Type::UUID),
                        (name, Type::TEXT),
                        (role, Type::TEXT_ARRAY),
                    ];
                    tx.execute_typed(sql::UPDATE_LAST_LOGIN, &p).await?
                }
                DeviceReport::Watchdog(running) => {
                    let p: [Param; 3] = [(t, Type::UUID), (d, Type::UUID), (running, Type::BOOL)];
                    tx.execute_typed(sql::UPDATE_WATCHDOG, &p).await?
                }
                DeviceReport::Version {
                    code,
                    name,
                    is_device_owner,
                    is_dev_device,
                } => {
                    let p: [Param; 6] = [
                        (t, Type::UUID),
                        (d, Type::UUID),
                        (code, Type::INT4),
                        (name, Type::TEXT),
                        (is_device_owner, Type::BOOL),
                        (is_dev_device, Type::BOOL),
                    ];
                    tx.execute_typed(sql::REPORT_VERSION, &p).await?
                }
            };
            Ok(true)
        })
    })
    .await
}

// --- 口 ---

/// 管理画面の口 (`X-Tenant-ID` の layer は [`crate::router`] が掛ける)
pub fn tenant_router() -> Router<AppState> {
    Router::new()
        .route("/devices", get(list_devices_handler))
        .route("/devices/pending", get(list_pending_handler))
        .route("/devices/register/create-token", post(create_url_token))
        .route(
            "/devices/register/create-permanent-qr",
            post(create_permanent_qr),
        )
        .route(
            "/devices/register/create-device-owner-token",
            post(create_device_owner_token),
        )
        .route("/devices/approve/{id}", post(approve_device))
        .route("/devices/approve-by-code/{code}", post(approve_by_code))
        .route("/devices/reject/{id}", post(reject_device))
        .route("/devices/disable/{id}", post(disable_device))
        .route("/devices/enable/{id}", post(enable_device))
        .route("/devices/{id}", delete(delete_device))
        .route("/devices/{id}/call-settings", put(call_settings_handler))
}

/// 端末の口と内部の口 (rust でもテナントの認証を持たない)
pub fn public_router() -> Router<AppState> {
    Router::new()
        .route(
            "/devices/register/request",
            post(create_registration_request_handler),
        )
        .route(
            "/devices/register/status/{code}",
            get(registration_status_handler),
        )
        .route("/devices/register/claim", post(claim_handler))
        .route("/devices/settings/{device_id}", get(settings_handler))
        .route("/devices/register-fcm-token", put(register_fcm_token))
        .route("/devices/update-last-login", put(update_last_login))
        .route("/devices/report-version", put(report_version))
        .route("/devices/report-watchdog", put(report_watchdog))
        .route(
            "/internal/devices/{device_id}/pairing-tenant",
            get(pairing_tenant_handler),
        )
}

async fn list_devices_handler(
    State(state): State<AppState>,
    Extension(TenantId(tenant_id)): Extension<TenantId>,
) -> Result<Json<Vec<Device>>, StatusCode> {
    let mut pg = state.pg.lock().await;
    list_devices(&mut pg, tenant_id)
        .await
        .map(Json)
        .map_err(|e| state.db_fail("list", &e))
}

async fn list_pending_handler(
    State(state): State<AppState>,
    Extension(TenantId(tenant_id)): Extension<TenantId>,
) -> Result<Json<Vec<RegistrationRequest>>, StatusCode> {
    let mut pg = state.pg.lock().await;
    list_pending(&mut pg, tenant_id)
        .await
        .map(Json)
        .map_err(|e| state.db_fail("pending", &e))
}

#[derive(Debug, Deserialize)]
pub struct CreateTokenBody {
    pub device_name: Option<String>,
    pub is_device_owner: Option<bool>,
    pub is_dev_device: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct CreateTokenResponse {
    pub registration_code: String,
    pub registration_url: String,
}

#[derive(Debug, Serialize)]
pub struct CodeResponse {
    pub registration_code: String,
}

async fn issue(
    state: &AppState,
    tenant_id: Uuid,
    kind: TokenKind,
    body: CreateTokenBody,
) -> Result<String, StatusCode> {
    let mut pg = state.pg.lock().await;
    create_token(
        &mut pg,
        tenant_id,
        kind,
        body.device_name.unwrap_or_default(),
        body.is_device_owner.unwrap_or(false),
        body.is_dev_device.unwrap_or(false),
    )
    .await
    .map_err(|e| state.db_fail("create token", &e))
}

async fn create_url_token(
    State(state): State<AppState>,
    Extension(TenantId(tenant_id)): Extension<TenantId>,
    Json(body): Json<CreateTokenBody>,
) -> Result<Json<CreateTokenResponse>, StatusCode> {
    let code = issue(&state, tenant_id, TokenKind::Url, body).await?;
    Ok(Json(CreateTokenResponse {
        registration_url: format!("/device-claim?token={code}"),
        registration_code: code,
    }))
}

async fn create_permanent_qr(
    State(state): State<AppState>,
    Extension(TenantId(tenant_id)): Extension<TenantId>,
    Json(body): Json<CreateTokenBody>,
) -> Result<Json<CodeResponse>, StatusCode> {
    let registration_code = issue(&state, tenant_id, TokenKind::PermanentQr, body).await?;
    Ok(Json(CodeResponse { registration_code }))
}

/// Device Owner の body の `is_device_owner` は見ない (rust と同じく常に true)
async fn create_device_owner_token(
    State(state): State<AppState>,
    Extension(TenantId(tenant_id)): Extension<TenantId>,
    Json(body): Json<CreateTokenBody>,
) -> Result<Json<CodeResponse>, StatusCode> {
    let registration_code = issue(&state, tenant_id, TokenKind::DeviceOwner, body).await?;
    Ok(Json(CodeResponse { registration_code }))
}

#[derive(Debug, Deserialize)]
pub struct ApproveBody {
    pub device_name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ApproveResponse {
    pub success: bool,
    pub device_id: Uuid,
    pub tenant_id: Uuid,
}

/// 承認の共通部分。`device_name` は body の名前 (コードでの承認は無し) → 登録の名前の順
async fn approve_common(
    state: &AppState,
    tenant_id: Uuid,
    auth: Option<AuthUser>,
    key: ApproveKey,
    device_name: Option<String>,
) -> Result<Json<ApproveResponse>, StatusCode> {
    let by_code = matches!(key, ApproveKey::Code(_));
    let mut pg = state.pg.lock().await;
    let target = find_approve_target(&mut pg, tenant_id, key)
        .await
        .map_err(|e| state.db_fail("approve lookup", &e))?;
    let Some(target) = target else {
        if by_code {
            // コードの総当たりの検知の手掛かり (識別子は出さない)
            (state.log)("devices: approve-by-code miss");
        }
        return Err(StatusCode::NOT_FOUND);
    };
    let new = NewDevice {
        device_name: device_name.unwrap_or(target.device_name),
        phone_number: target.phone_number,
        approved_by: auth.map(|a| a.user_id),
        is_device_owner: target.is_device_owner,
        is_dev_device: target.is_dev_device,
    };
    let device_id = approve(&mut pg, tenant_id, target.id, new)
        .await
        .map_err(|e| state.db_fail("approve", &e))?;
    Ok(Json(ApproveResponse {
        success: true,
        device_id,
        tenant_id,
    }))
}

async fn approve_device(
    State(state): State<AppState>,
    Extension(TenantId(tenant_id)): Extension<TenantId>,
    auth: Option<Extension<AuthUser>>,
    Path(id): Path<Uuid>,
    Json(body): Json<ApproveBody>,
) -> Result<Json<ApproveResponse>, StatusCode> {
    let auth = auth.map(|Extension(a)| a);
    approve_common(
        &state,
        tenant_id,
        auth,
        ApproveKey::Id(id),
        body.device_name,
    )
    .await
}

async fn approve_by_code(
    State(state): State<AppState>,
    Extension(TenantId(tenant_id)): Extension<TenantId>,
    auth: Option<Extension<AuthUser>>,
    Path(code): Path<String>,
) -> Result<Json<ApproveResponse>, StatusCode> {
    let auth = auth.map(|Extension(a)| a);
    approve_common(&state, tenant_id, auth, ApproveKey::Code(code), None).await
}

/// 却下・停止・再開・削除の共通部分 (行が無ければ 404、在れば 204)
async fn by_id(
    state: &AppState,
    tenant_id: Uuid,
    statement: &'static str,
    stage: &str,
    id: Uuid,
) -> Result<StatusCode, StatusCode> {
    let mut pg = state.pg.lock().await;
    let found = exec_by_id(&mut pg, tenant_id, statement, id)
        .await
        .map_err(|e| state.db_fail(stage, &e))?;
    if found {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

async fn reject_device(
    State(state): State<AppState>,
    Extension(TenantId(tenant_id)): Extension<TenantId>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, StatusCode> {
    by_id(&state, tenant_id, sql::REJECT, "reject", id).await
}

async fn disable_device(
    State(state): State<AppState>,
    Extension(TenantId(tenant_id)): Extension<TenantId>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, StatusCode> {
    by_id(&state, tenant_id, sql::DISABLE, "disable", id).await
}

async fn enable_device(
    State(state): State<AppState>,
    Extension(TenantId(tenant_id)): Extension<TenantId>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, StatusCode> {
    by_id(&state, tenant_id, sql::ENABLE, "enable", id).await
}

async fn delete_device(
    State(state): State<AppState>,
    Extension(TenantId(tenant_id)): Extension<TenantId>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, StatusCode> {
    by_id(&state, tenant_id, sql::DELETE, "delete", id).await
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpdateCallSettingsBody {
    pub call_enabled: bool,
    pub call_schedule: Option<Value>,
    pub always_on: Option<bool>,
    pub bp_enabled: Option<bool>,
}

async fn call_settings_handler(
    State(state): State<AppState>,
    Extension(TenantId(tenant_id)): Extension<TenantId>,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateCallSettingsBody>,
) -> Result<StatusCode, StatusCode> {
    let mut pg = state.pg.lock().await;
    let found = update_call_settings(&mut pg, tenant_id, id, body)
        .await
        .map_err(|e| state.db_fail("call settings", &e))?;
    if found {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

// --- 端末の口 ---

#[derive(Debug, Deserialize)]
pub struct CreateRegistrationRequestBody {
    pub device_name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CreateRegistrationResponse {
    pub registration_code: String,
    pub expires_at: String,
}

async fn create_registration_request_handler(
    State(state): State<AppState>,
    Json(body): Json<CreateRegistrationRequestBody>,
) -> Result<Json<CreateRegistrationResponse>, StatusCode> {
    let mut pg = state.pg.lock().await;
    let (registration_code, expires_at) =
        create_registration_request(&mut pg, body.device_name.unwrap_or_default())
            .await
            .map_err(|e| state.db_fail("register request", &e))?;
    Ok(Json(CreateRegistrationResponse {
        registration_code,
        expires_at,
    }))
}

/// rust の `RegistrationStatusResponse`。approved になるまで端末・テナント・名前・token は返さない
#[derive(Debug, Serialize)]
pub struct RegistrationStatusResponse {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settings_token: Option<Uuid>,
}

impl From<RegistrationStatus> for RegistrationStatusResponse {
    fn from(r: RegistrationStatus) -> Self {
        let status = if r.status == "pending" && r.expired {
            "expired".to_owned()
        } else {
            r.status
        };
        let approved = status == "approved";
        Self {
            status,
            device_id: r.device_id.filter(|_| approved),
            tenant_id: r.tenant_id.filter(|_| approved),
            device_name: r.device_name.filter(|_| approved),
            settings_token: r.settings_token.filter(|_| approved),
        }
    }
}

async fn registration_status_handler(
    State(state): State<AppState>,
    Path(code): Path<String>,
) -> Result<Json<RegistrationStatusResponse>, StatusCode> {
    let mut pg = state.pg.lock().await;
    registration_status(&mut pg, code)
        .await
        .map_err(|e| state.db_fail("register status", &e))?
        .map(|r| Json(r.into()))
        .ok_or(StatusCode::NOT_FOUND)
}

#[derive(Debug, Deserialize)]
pub struct ClaimRegistrationBody {
    pub registration_code: String,
    pub phone_number: Option<String>,
    pub device_name: Option<String>,
}

/// rust の `ClaimRegistrationResponse`
#[derive(Debug, Serialize)]
pub struct ClaimRegistrationResponse {
    pub success: bool,
    pub flow_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settings_token: Option<Uuid>,
}

type ClaimError = (StatusCode, Json<ClaimRegistrationResponse>);

/// 受け取りの失敗 (rust と同じく 400 と文言。DB の失敗も 400 の "internal error")
fn claim_err(message: &str) -> ClaimError {
    (
        StatusCode::BAD_REQUEST,
        Json(ClaimRegistrationResponse {
            success: false,
            flow_type: String::new(),
            device_id: None,
            tenant_id: None,
            message: Some(message.to_owned()),
            settings_token: None,
        }),
    )
}

async fn claim_handler(
    State(state): State<AppState>,
    Json(body): Json<ClaimRegistrationBody>,
) -> Result<Json<ClaimRegistrationResponse>, ClaimError> {
    let db = |stage: &str, e: &Error| {
        let _ = state.db_fail(stage, e);
        claim_err("internal error")
    };
    let mut pg = state.pg.lock().await;
    let req = find_claim(&mut pg, body.registration_code)
        .await
        .map_err(|e| db("claim lookup", &e))?
        .ok_or_else(|| claim_err("無効な登録コードです"))?;
    if req.status != "pending" {
        return Err(claim_err("このコードは既に使用済みです"));
    }
    // 端末の入力があればそちら、無ければ管理者が付けた名前
    let device_name = body
        .device_name
        .filter(|s| !s.is_empty())
        .unwrap_or(req.device_name);
    let flow = req.flow_type.as_str();
    if !matches!(flow, "url" | "device_owner" | "qr_permanent") {
        return Err(claim_err("無効なフロータイプです"));
    }
    let tenant_id = req
        .tenant_id
        .ok_or_else(|| claim_err("無効なトークンです"))?;
    if flow == "qr_permanent" {
        // 承認待ちのまま (管理者の承認を待つ)
        claim_permanent_qr(&mut pg, tenant_id, req.id, body.phone_number, device_name)
            .await
            .map_err(|e| db("claim permanent qr", &e))?;
        return Ok(Json(ClaimRegistrationResponse {
            success: true,
            flow_type: "qr_permanent".to_owned(),
            device_id: None,
            tenant_id: None,
            message: Some("管理者の承認待ちです".to_owned()),
            settings_token: None,
        }));
    }
    // URL・Device Owner は即登録
    let new = NewDevice {
        device_name,
        phone_number: body.phone_number,
        approved_by: None,
        is_device_owner: flow == "device_owner" || req.is_device_owner,
        is_dev_device: req.is_dev_device,
    };
    let (device_id, settings_token) = claim_device(&mut pg, tenant_id, req.id, new)
        .await
        .map_err(|e| db("claim", &e))?;
    Ok(Json(ClaimRegistrationResponse {
        success: true,
        flow_type: req.flow_type,
        device_id: Some(device_id),
        tenant_id: Some(tenant_id),
        message: None,
        settings_token: Some(settings_token),
    }))
}

/// rust の `DeviceSettingsResponse` (settings_token は返さない)
#[derive(Debug, Serialize)]
pub struct DeviceSettingsResponse {
    pub call_enabled: bool,
    pub call_schedule: Option<Value>,
    pub status: String,
    pub last_login_employee_id: Option<Uuid>,
    pub last_login_employee_name: Option<String>,
    pub last_login_employee_role: Option<Vec<String>>,
    pub always_on: bool,
    pub bp_enabled: bool,
}

impl From<DeviceSettings> for DeviceSettingsResponse {
    fn from(r: DeviceSettings) -> Self {
        Self {
            call_enabled: r.call_enabled,
            call_schedule: r.call_schedule,
            status: r.status,
            last_login_employee_id: r.last_login_employee_id,
            last_login_employee_name: r.last_login_employee_name,
            last_login_employee_role: r.last_login_employee_role,
            always_on: r.always_on,
            bp_enabled: r.bp_enabled,
        }
    }
}

/// `X-Device-Token` の照合 (rust と同じ移行期の扱い): 送られたら厳格に照合 (違えば 401)、token 発行済みなのに
/// 送られなければ記録だけして通す、旧端末 (未発行・未送信) はそのまま。返すのは「通す」か
pub fn device_token_ok(provided: Option<&str>, issued: Option<Uuid>) -> Result<bool, StatusCode> {
    match (provided, issued) {
        (Some(p), Some(t)) if alc_core_wasm_eq(p, &t.to_string()) => Ok(true),
        (Some(_), _) => Err(StatusCode::UNAUTHORIZED),
        (None, Some(_)) => Ok(false),
        (None, None) => Ok(true),
    }
}

/// 長さの漏れない比較 (rust の `constant_time_eq` と同じ働き)
fn alc_core_wasm_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

async fn settings_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(device_id): Path<Uuid>,
) -> Result<Json<DeviceSettingsResponse>, StatusCode> {
    let row = {
        let mut pg = state.pg.lock().await;
        device_settings(&mut pg, device_id)
            .await
            .map_err(|e| state.db_fail("settings", &e))?
            .ok_or(StatusCode::NOT_FOUND)?
    };
    let provided = headers.get("X-Device-Token").and_then(|v| v.to_str().ok());
    if !device_token_ok(provided, row.settings_token)? {
        (state.log)("devices: settings token not sent");
    }
    Ok(Json(row.into()))
}

/// 端末からの更新の共通部分 (端末が無ければ 404、在れば 204)
async fn device_report(
    state: &AppState,
    stage: &str,
    device_id: Uuid,
    r: DeviceReport,
) -> Result<StatusCode, StatusCode> {
    let mut pg = state.pg.lock().await;
    let found = report(&mut pg, device_id, r)
        .await
        .map_err(|e| state.db_fail(stage, &e))?;
    if found {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

#[derive(Debug, Deserialize)]
pub struct RegisterFcmTokenBody {
    pub device_id: Uuid,
    pub fcm_token: String,
}

async fn register_fcm_token(
    State(state): State<AppState>,
    Json(body): Json<RegisterFcmTokenBody>,
) -> Result<StatusCode, StatusCode> {
    let r = DeviceReport::FcmToken(body.fcm_token);
    device_report(&state, "fcm token", body.device_id, r).await
}

#[derive(Debug, Deserialize)]
pub struct UpdateLastLoginBody {
    pub device_id: Uuid,
    pub employee_id: Uuid,
    pub employee_name: String,
    pub employee_role: Vec<String>,
}

async fn update_last_login(
    State(state): State<AppState>,
    Json(body): Json<UpdateLastLoginBody>,
) -> Result<StatusCode, StatusCode> {
    let r = DeviceReport::LastLogin {
        employee_id: body.employee_id,
        name: body.employee_name,
        role: body.employee_role,
    };
    device_report(&state, "last login", body.device_id, r).await
}

#[derive(Debug, Deserialize)]
pub struct ReportVersionBody {
    pub device_id: Uuid,
    pub version_code: i32,
    pub version_name: String,
    #[serde(default)]
    pub is_device_owner: bool,
    #[serde(default)]
    pub is_dev_device: bool,
}

async fn report_version(
    State(state): State<AppState>,
    Json(body): Json<ReportVersionBody>,
) -> Result<StatusCode, StatusCode> {
    let r = DeviceReport::Version {
        code: body.version_code,
        name: body.version_name,
        is_device_owner: body.is_device_owner,
        is_dev_device: body.is_dev_device,
    };
    device_report(&state, "report version", body.device_id, r).await
}

#[derive(Debug, Deserialize)]
pub struct ReportWatchdogBody {
    pub device_id: Uuid,
    pub running: bool,
}

async fn report_watchdog(
    State(state): State<AppState>,
    Json(body): Json<ReportWatchdogBody>,
) -> Result<StatusCode, StatusCode> {
    let r = DeviceReport::Watchdog(body.running);
    device_report(&state, "report watchdog", body.device_id, r).await
}

#[derive(Debug, Serialize)]
pub struct PairingTenantResponse {
    pub tenant_id: Uuid,
}

async fn pairing_tenant_handler(
    State(state): State<AppState>,
    Path(device_id): Path<Uuid>,
) -> Result<Json<PairingTenantResponse>, StatusCode> {
    let mut pg = state.pg.lock().await;
    pairing_tenant(&mut pg, device_id)
        .await
        .map_err(|e| state.db_fail("pairing tenant", &e))?
        .map(|tenant_id| Json(PairingTenantResponse { tenant_id }))
        .ok_or(StatusCode::NOT_FOUND)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(status: &str, expired: bool) -> RegistrationStatus {
        RegistrationStatus {
            status: status.to_owned(),
            device_id: Some(Uuid::nil()),
            tenant_id: Some(Uuid::nil()),
            expired,
            device_name: Some("端末".to_owned()),
            settings_token: Some(Uuid::nil()),
        }
    }

    #[test]
    fn registration_status_hides_details_until_approved() {
        let pending = RegistrationStatusResponse::from(status("pending", false));
        assert_eq!(pending.status, "pending");
        assert!(pending.device_id.is_none() && pending.tenant_id.is_none());
        assert!(pending.device_name.is_none() && pending.settings_token.is_none());
        assert_eq!(
            RegistrationStatusResponse::from(status("pending", true)).status,
            "expired"
        );
        // 期限切れは pending のときだけ (approved は期限を過ぎても approved)
        let approved = RegistrationStatusResponse::from(status("approved", true));
        assert_eq!(approved.status, "approved");
        assert!(approved.device_id.is_some() && approved.settings_token.is_some());
    }

    #[test]
    fn device_token_matches_rust_transition_rules() {
        let t = Uuid::from_u128(7);
        assert_eq!(device_token_ok(Some(&t.to_string()), Some(t)), Ok(true));
        assert_eq!(
            device_token_ok(Some("x"), Some(t)),
            Err(StatusCode::UNAUTHORIZED)
        );
        assert_eq!(
            device_token_ok(Some("x"), None),
            Err(StatusCode::UNAUTHORIZED)
        );
        assert_eq!(device_token_ok(None, Some(t)), Ok(false));
        assert_eq!(device_token_ok(None, None), Ok(true));
        assert!(!alc_core_wasm_eq("ab", "abc"));
    }

    #[test]
    fn device_type_follows_phone_number() {
        let mut d = NewDevice {
            device_name: String::new(),
            phone_number: None,
            approved_by: None,
            is_device_owner: false,
            is_dev_device: false,
        };
        assert_eq!(d.device_type(), "kiosk");
        d.phone_number = Some("090".to_owned());
        assert_eq!(d.device_type(), "android");
    }
}
