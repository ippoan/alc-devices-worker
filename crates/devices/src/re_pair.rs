//! kiosk 端末の再ペアリング (W6b-b、Refs ippoan/rust-alc-api#680。rust の `alc-devices` の re_pair_policy.rs と
//! devices.rs の `re_pair`・`authorize_repair`、repo/devices.rs の写し。設計の正本は rust-alc-api の docs/plan-device-repair.md)。
//!
//! - `POST /devices/{id}/authorize-repair` (管理画面、テナント付き) — 時限の window を開ける (`{reset_binding}` で
//!   端末の hardware_id の結び付きも外す)。有効な端末でなければ 404
//! - `POST /devices/re-pair` (端末、テナント無し) — window の中で、auth-worker から device credential を取り直す。
//!   判定 ([`evaluate`]) が通れば発行 ([`DevicePairer`]) → window を消費 (compare-and-swap)。拒否の理由は返さず 404、
//!   cooldown 中だけ 429。応答は `Cache-Control: no-store`
//!
//! 判定の値は rust の既定値 (本番の Cloud Run は `RE_PAIR_*` を設定していない): window 900 秒・cooldown 600 秒・
//! admin の window を要る・settings_token の照合はしない ([`POLICY`])。判定の「今」は DB の `now()` を使う。
//!
//! rust との違い: 発行は auth-worker の RPC (`DevicePairEntrypoint.pairInternal`、Service Binding) で、共有の秘密を持たない。
//! ログは固定の語だけ (端末の ID・テナントを出さない)。SQL に tenant_id も書く。

use std::sync::Arc;

use alc_core_wasm::TenantId;
use alc_worker_db::{PgClient, TxOutput};
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::routing::post;
use axum::{Extension, Json, Router};
use chrono::{DateTime, Duration, Utc};
use futures_util::future::BoxFuture;
use serde::{Deserialize, Serialize};
use tokio_postgres::types::{ToSql, Type};
use tokio_postgres::Error;
use uuid::Uuid;

use crate::AppState;

/// 判定の値 (rust の `RePairPolicy`)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    pub require_admin_window: bool,
    pub require_settings_token: bool,
    pub cooldown_secs: i64,
}

/// 本番の値 (rust の既定値。Cloud Run は `RE_PAIR_*` を設定していない)
pub const POLICY: Policy = Policy {
    require_admin_window: true,
    require_settings_token: false,
    cooldown_secs: 600,
};

/// 管理者が開ける window の長さ (rust の `RE_PAIR_WINDOW_SECS` の既定値)
pub const WINDOW_SECS: i64 = 900;

/// 発行する credential の label の頭 (rust と同じ `alc-app:{device_id}`)
pub const LABEL_PREFIX: &str = "alc-app:";

/// 判定の入力 (DB から読んだ今の状態と、端末の申告。rust の `RePairContext`)
#[derive(Debug, Clone)]
pub struct Context {
    pub status: String,
    pub authorized_until: Option<DateTime<Utc>>,
    pub last_re_pair_at: Option<DateTime<Utc>>,
    pub bound_hardware_id: Option<String>,
    pub requested_hardware_id: Option<String>,
    pub provided_settings_token: Option<Uuid>,
    pub stored_settings_token: Option<Uuid>,
}

/// 判定の結果 (rust の `RePairDecision`)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// 通す。`bind_hardware_id` が在れば、今回の hardware_id を初めての結び付きとして書く
    Allow { bind_hardware_id: Option<String> },
    /// 拒否 (理由は返さず 404)
    DenyNotFound,
    /// cooldown 中 (429)
    DenyTooManyRequests,
}

/// 判定 (rust の `evaluate_re_pair_request` と同じ順: 状態 → admin の window → cooldown → hardware の結び付き → settings_token)
pub fn evaluate(ctx: &Context, policy: &Policy, now: DateTime<Utc>) -> Decision {
    if ctx.status != "active" {
        return Decision::DenyNotFound;
    }
    if policy.require_admin_window && ctx.authorized_until.is_none_or(|until| until <= now) {
        return Decision::DenyNotFound;
    }
    if ctx
        .last_re_pair_at
        .is_some_and(|last| now - last < Duration::seconds(policy.cooldown_secs))
    {
        return Decision::DenyTooManyRequests;
    }
    let bind_hardware_id = match (&ctx.bound_hardware_id, &ctx.requested_hardware_id) {
        (Some(bound), Some(requested)) if bound != requested => return Decision::DenyNotFound,
        (None, Some(requested)) => Some(requested.clone()),
        _ => None,
    };
    // 申告が無いのは通す (rust と同じ ratchet)
    if policy.require_settings_token
        && ctx
            .provided_settings_token
            .is_some_and(|provided| ctx.stored_settings_token != Some(provided))
    {
        return Decision::DenyNotFound;
    }
    Decision::Allow { bind_hardware_id }
}

/// 発行された credential (auth-worker の device_id と平文の secret)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairedCredential {
    pub device_id: String,
    pub device_secret: String,
}

/// 発行の失敗 (理由は持たない。呼び手は 404 にする)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PairError;

/// device credential の発行 (Workers では auth-worker の RPC `DevicePairEntrypoint.pairInternal`、テストは偽物)
pub trait DevicePairer: Send + Sync {
    fn pair<'a>(
        &'a self,
        device_id: Uuid,
        label: &'a str,
    ) -> BoxFuture<'a, Result<PairedCredential, PairError>>;
}

pub type SharedPairer = Arc<dyn DevicePairer>;

pub mod sql {
    /// 端末の再ペアリングの状態と DB の今。$1 端末の ID (テナントに依らない SECURITY DEFINER の関数)
    pub const STATE: &str =
        "SELECT tenant_id, status, re_pair_authorized_until, last_re_pair_at, hardware_id, \
         settings_token, now() FROM alc_api.get_device_re_pair_state($1)";

    /// 成功を記録して window を消費する (判定で読んだ window と同じときだけ = compare-and-swap)。
    /// $1 結び付ける hardware_id (NULL なら今のまま) / $2 端末の ID / $3 読んだ window / $4 tenant_id
    pub const RECORD_SUCCESS: &str = "UPDATE alc_api.devices \
         SET re_pair_authorized_until = NULL, last_re_pair_at = now(), re_pair_count = re_pair_count + 1, \
             hardware_id = COALESCE(hardware_id, $1), updated_at = now() \
         WHERE id = $2 AND tenant_id = $4 AND re_pair_authorized_until IS NOT DISTINCT FROM $3";

    /// window を開ける (有効な端末だけ)。$1 秒数 / $2 結び付きを外すか / $3 端末の ID / $4 tenant_id → 開いた window の終わり
    pub const AUTHORIZE: &str = "UPDATE alc_api.devices \
         SET re_pair_authorized_until = now() + make_interval(secs => $1::double precision), \
             hardware_id = CASE WHEN $2 THEN NULL ELSE hardware_id END, updated_at = now() \
         WHERE id = $3 AND tenant_id = $4 AND status = 'active' \
         RETURNING re_pair_authorized_until";
}

/// [`sql::STATE`] の 1 行
#[derive(Debug, Clone, PartialEq)]
pub struct RePairState {
    pub tenant_id: Uuid,
    pub status: String,
    pub authorized_until: Option<DateTime<Utc>>,
    pub last_re_pair_at: Option<DateTime<Utc>>,
    pub hardware_id: Option<String>,
    pub settings_token: Option<Uuid>,
    pub now: DateTime<Utc>,
}

impl TxOutput for RePairState {}

/// 端末の状態 (テナントの決まる前なので nil のテナントの transaction。関数は SECURITY DEFINER)
pub async fn load_state(pg: &mut PgClient, device_id: Uuid) -> Result<Option<RePairState>, Error> {
    pg.tenant_tx(Uuid::nil(), move |tx| {
        Box::pin(async move {
            Ok(tx
                .query_typed_opt(sql::STATE, &[(&device_id, Type::UUID)])
                .await?
                .map(|r| RePairState {
                    tenant_id: r.get(0),
                    status: r.get(1),
                    authorized_until: r.get(2),
                    last_re_pair_at: r.get(3),
                    hardware_id: r.get(4),
                    settings_token: r.get(5),
                    now: r.get(6),
                }))
        })
    })
    .await
}

/// 成功の記録 ([`sql::RECORD_SUCCESS`])。window を消費できたら true
pub async fn record_success(
    pg: &mut PgClient,
    tenant_id: Uuid,
    device_id: Uuid,
    expected_until: Option<DateTime<Utc>>,
    bind_hardware_id: Option<String>,
) -> Result<bool, Error> {
    pg.tenant_tx(tenant_id, move |tx| {
        Box::pin(async move {
            let args: [(&(dyn ToSql + Sync), Type); 4] = [
                (&bind_hardware_id, Type::TEXT),
                (&device_id, Type::UUID),
                (&expected_until, Type::TIMESTAMPTZ),
                (&tenant_id, Type::UUID),
            ];
            Ok(tx.execute_typed(sql::RECORD_SUCCESS, &args).await? > 0)
        })
    })
    .await
}

/// window を開ける ([`sql::AUTHORIZE`])。有効な端末が無ければ None
pub async fn authorize(
    pg: &mut PgClient,
    tenant_id: Uuid,
    device_id: Uuid,
    reset_binding: bool,
) -> Result<Option<DateTime<Utc>>, Error> {
    pg.tenant_tx(tenant_id, move |tx| {
        Box::pin(async move {
            let args: [(&(dyn ToSql + Sync), Type); 4] = [
                (&WINDOW_SECS, Type::INT8),
                (&reset_binding, Type::BOOL),
                (&device_id, Type::UUID),
                (&tenant_id, Type::UUID),
            ];
            Ok(tx
                .query_typed_opt(sql::AUTHORIZE, &args)
                .await?
                .map(|r| r.get::<_, DateTime<Utc>>(0)))
        })
    })
    .await
}

// --- 口 ---

/// 管理画面の口 (テナント付き)
pub fn tenant_router() -> Router<AppState> {
    Router::new().route("/devices/{id}/authorize-repair", post(authorize_handler))
}

/// 端末の口 (テナント無し)
pub fn public_router() -> Router<AppState> {
    Router::new().route("/devices/re-pair", post(re_pair_handler))
}

#[derive(Debug, Default, Deserialize)]
pub struct AuthorizeBody {
    #[serde(default)]
    pub reset_binding: bool,
}

#[derive(Debug, Serialize)]
pub struct AuthorizeResponse {
    pub authorized_until: DateTime<Utc>,
}

async fn authorize_handler(
    State(state): State<AppState>,
    Extension(TenantId(tenant_id)): Extension<TenantId>,
    Path(id): Path<Uuid>,
    Json(body): Json<AuthorizeBody>,
) -> Result<Json<AuthorizeResponse>, StatusCode> {
    let mut pg = state.pg.lock().await;
    authorize(&mut pg, tenant_id, id, body.reset_binding)
        .await
        .map_err(|e| state.db_fail("authorize-repair", &e))?
        .map(|authorized_until| Json(AuthorizeResponse { authorized_until }))
        .ok_or(StatusCode::NOT_FOUND)
}

#[derive(Debug, Deserialize)]
pub struct RePairBody {
    pub device_id: Uuid,
    #[serde(default)]
    pub hardware_id: Option<String>,
    #[serde(default)]
    pub settings_token: Option<Uuid>,
}

#[derive(Debug, Serialize)]
pub struct RePairResponse {
    pub auth_device_id: String,
    pub device_secret: String,
}

async fn re_pair_handler(
    State(state): State<AppState>,
    Json(body): Json<RePairBody>,
) -> Result<(HeaderMap, Json<RePairResponse>), StatusCode> {
    let mut no_store = HeaderMap::new();
    no_store.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));

    let row = {
        let mut pg = state.pg.lock().await;
        load_state(&mut pg, body.device_id)
            .await
            .map_err(|e| state.db_fail("re-pair lookup", &e))?
            .ok_or(StatusCode::NOT_FOUND)?
    };
    let ctx = Context {
        status: row.status.clone(),
        authorized_until: row.authorized_until,
        last_re_pair_at: row.last_re_pair_at,
        bound_hardware_id: row.hardware_id.clone(),
        requested_hardware_id: body.hardware_id.clone(),
        provided_settings_token: body.settings_token,
        stored_settings_token: row.settings_token,
    };
    let bind_hardware_id = match evaluate(&ctx, &POLICY, row.now) {
        Decision::DenyNotFound => {
            (state.log)("devices: re-pair denied (not_found)");
            return Err(StatusCode::NOT_FOUND);
        }
        Decision::DenyTooManyRequests => {
            (state.log)("devices: re-pair denied (cooldown)");
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
        Decision::Allow { bind_hardware_id } => bind_hardware_id,
    };

    let Some(pairer) = state.pairer.as_ref() else {
        (state.log)("devices: re-pair pairer not configured");
        return Err(StatusCode::NOT_FOUND);
    };
    let label = format!("{LABEL_PREFIX}{}", body.device_id);
    let credential = pairer.pair(body.device_id, &label).await.map_err(|_| {
        (state.log)("devices: re-pair pair failed");
        StatusCode::NOT_FOUND
    })?;

    let consumed = {
        let mut pg = state.pg.lock().await;
        record_success(
            &mut pg,
            row.tenant_id,
            body.device_id,
            row.authorized_until,
            bind_hardware_id,
        )
        .await
        .map_err(|e| state.db_fail("re-pair record", &e))?
    };
    if !consumed {
        (state.log)("devices: re-pair denied (window already consumed)");
        return Err(StatusCode::NOT_FOUND);
    }

    Ok((
        no_store,
        Json(RePairResponse {
            auth_device_id: credential.device_id,
            device_secret: credential.device_secret,
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> Context {
        Context {
            status: "active".to_owned(),
            authorized_until: None,
            last_re_pair_at: None,
            bound_hardware_id: None,
            requested_hardware_id: None,
            provided_settings_token: None,
            stored_settings_token: None,
        }
    }

    fn now() -> DateTime<Utc> {
        DateTime::from_timestamp(1_800_000_000, 0).unwrap()
    }

    fn open(mut c: Context) -> Context {
        c.authorized_until = Some(now() + Duration::minutes(5));
        c
    }

    #[test]
    fn status_and_admin_window() {
        let mut disabled = open(ctx());
        disabled.status = "disabled".to_owned();
        assert_eq!(evaluate(&disabled, &POLICY, now()), Decision::DenyNotFound);
        assert_eq!(evaluate(&ctx(), &POLICY, now()), Decision::DenyNotFound);
        let mut expired = ctx();
        expired.authorized_until = Some(now() - Duration::seconds(1));
        assert_eq!(evaluate(&expired, &POLICY, now()), Decision::DenyNotFound);
        assert_eq!(
            evaluate(&open(ctx()), &POLICY, now()),
            Decision::Allow {
                bind_hardware_id: None
            }
        );
        let no_window = Policy {
            require_admin_window: false,
            ..POLICY
        };
        assert_eq!(
            evaluate(&ctx(), &no_window, now()),
            Decision::Allow {
                bind_hardware_id: None
            }
        );
    }

    #[test]
    fn cooldown() {
        let mut recent = open(ctx());
        recent.last_re_pair_at = Some(now() - Duration::seconds(599));
        assert_eq!(
            evaluate(&recent, &POLICY, now()),
            Decision::DenyTooManyRequests
        );
        recent.last_re_pair_at = Some(now() - Duration::seconds(600));
        assert_eq!(
            evaluate(&recent, &POLICY, now()),
            Decision::Allow {
                bind_hardware_id: None
            }
        );
    }

    #[test]
    fn hardware_binding() {
        let mut first = open(ctx());
        first.requested_hardware_id = Some("hw-1".to_owned());
        assert_eq!(
            evaluate(&first, &POLICY, now()),
            Decision::Allow {
                bind_hardware_id: Some("hw-1".to_owned())
            }
        );
        let mut same = first.clone();
        same.bound_hardware_id = Some("hw-1".to_owned());
        assert_eq!(
            evaluate(&same, &POLICY, now()),
            Decision::Allow {
                bind_hardware_id: None
            }
        );
        let mut other = first;
        other.bound_hardware_id = Some("hw-2".to_owned());
        assert_eq!(evaluate(&other, &POLICY, now()), Decision::DenyNotFound);
    }

    #[test]
    fn settings_token_only_when_required_and_provided() {
        let token = Uuid::from_u128(1);
        let strict = Policy {
            require_settings_token: true,
            ..POLICY
        };
        let mut c = open(ctx());
        c.provided_settings_token = Some(token);
        // 既定 (本番) は照合しない
        assert!(matches!(
            evaluate(&c, &POLICY, now()),
            Decision::Allow { .. }
        ));
        assert_eq!(evaluate(&c, &strict, now()), Decision::DenyNotFound);
        c.stored_settings_token = Some(token);
        assert!(matches!(
            evaluate(&c, &strict, now()),
            Decision::Allow { .. }
        ));
        c.provided_settings_token = None;
        c.stored_settings_token = Some(Uuid::from_u128(2));
        assert!(matches!(
            evaluate(&c, &strict, now()),
            Decision::Allow { .. }
        ));
    }
}
