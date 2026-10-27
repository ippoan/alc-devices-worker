//! kiosk 端末の再ペアリング (W6b-b) を実 DB で通す (rust-alc-api の devices の re_pair・authorize_repair の要点)。
//! 発行 (auth-worker の RPC) は偽物を差す。接続は本番の worker と同じ実行用ロール `alc_api_rt` (RLS が効く)。

mod support;

use std::sync::{Arc, Mutex as StdMutex};

use devices::re_pair::{
    DevicePairer, PairError, PairedCredential, SharedPairer, LABEL_PREFIX, WINDOW_SECS,
};
use futures_util::future::BoxFuture;
use serde_json::{json, Value};
use support::{
    admin, backend_pid, broken_client, build, build_with, call, rt_client, tenant, terminate,
};
use uuid::Uuid;

/// 偽の発行。呼ばれた (端末の ID, label) を覚え、`before` を走らせてから結果を返す
struct FakePairer {
    calls: StdMutex<Vec<(Uuid, String)>>,
    ok: bool,
    before: Option<Box<dyn Fn(Uuid) -> BoxFuture<'static, ()> + Send + Sync>>,
}

impl FakePairer {
    fn new(ok: bool) -> Self {
        Self {
            calls: StdMutex::new(Vec::new()),
            ok,
            before: None,
        }
    }
}

impl DevicePairer for FakePairer {
    fn pair<'a>(
        &'a self,
        device_id: Uuid,
        label: &'a str,
    ) -> BoxFuture<'a, Result<PairedCredential, PairError>> {
        Box::pin(async move {
            self.calls
                .lock()
                .unwrap()
                .push((device_id, label.to_owned()));
            if let Some(before) = &self.before {
                before(device_id).await;
            }
            if self.ok {
                Ok(PairedCredential {
                    device_id: "auth-dev-1".to_owned(),
                    device_secret: "secret-1".to_owned(),
                })
            } else {
                Err(PairError)
            }
        })
    }
}

/// 端末の行 (superuser で)。hardware_id を結び付けておくか選ぶ
async fn device(tenant: Uuid, status: &str, hardware: Option<&str>) -> Uuid {
    admin()
        .await
        .query_one(
            "INSERT INTO alc_api.devices (tenant_id, device_name, status, hardware_id) VALUES ($1, '端末', $2, $3) RETURNING id",
            &[&tenant, &status, &hardware],
        )
        .await
        .unwrap()
        .get(0)
}

/// (window が開いているか, 再ペアリングの回数, 最後の再ペアリングが在るか, hardware_id)
async fn row(id: Uuid) -> (bool, i32, bool, Option<String>) {
    let r = admin()
        .await
        .query_one(
            "SELECT re_pair_authorized_until IS NOT NULL, re_pair_count, last_re_pair_at IS NOT NULL, hardware_id \
             FROM alc_api.devices WHERE id = $1",
            &[&id],
        )
        .await
        .unwrap();
    (r.get(0), r.get(1), r.get(2), r.get(3))
}

fn re_pair(device: Uuid, hardware: Option<&str>) -> Value {
    json!({ "device_id": device, "hardware_id": hardware })
}

/// 管理画面: 有効な自テナントの端末にだけ window を開ける (900 秒)。`reset_binding` で結び付きを外す
#[tokio::test]
async fn authorize_opens_the_window() {
    let app = support::app().await;
    let t = tenant().await;
    let other = tenant().await;
    let id = device(t, "active", Some("hw-1")).await;
    let disabled = device(t, "disabled", None).await;
    let uri = |d: Uuid| format!("/api/devices/{d}/authorize-repair");

    assert_eq!(
        call(&app, "POST", &uri(id), None, Some(json!({})))
            .await
            .status,
        401
    );
    for (d, tn) in [(Uuid::new_v4(), t), (disabled, t), (id, other)] {
        assert_eq!(
            call(&app, "POST", &uri(d), Some(tn), Some(json!({})))
                .await
                .status,
            404
        );
    }

    let got = call(&app, "POST", &uri(id), Some(t), Some(json!({}))).await;
    assert_eq!(got.status, 200);
    let until = got.json()["authorized_until"].as_str().unwrap().to_owned();
    let secs: f64 = admin()
        .await
        .query_one(
            "SELECT EXTRACT(EPOCH FROM ($1::text::timestamptz - now()))::float8",
            &[&until],
        )
        .await
        .unwrap()
        .get(0);
    assert!(
        (WINDOW_SECS as f64 - 60.0..=WINDOW_SECS as f64).contains(&secs),
        "{secs}"
    );
    assert_eq!(row(id).await.3.as_deref(), Some("hw-1"));

    let got = call(
        &app,
        "POST",
        &uri(id),
        Some(t),
        Some(json!({ "reset_binding": true })),
    )
    .await;
    assert_eq!(got.status, 200);
    assert_eq!(row(id).await.3, None);
    assert!(app.logs().is_empty());
}

/// 端末: window の中だけ発行し、window を消費して回数を数え、初めての hardware_id を結び付ける。no-store
#[tokio::test]
async fn re_pair_issues_once_per_window() {
    let pairer = Arc::new(FakePairer::new(true));
    let app = build_with(rt_client().await, Some(pairer.clone() as SharedPairer));
    let t = tenant().await;
    let id = device(t, "active", None).await;
    let authorize_uri = format!("/api/devices/{id}/authorize-repair");
    let authorize = || call(&app, "POST", &authorize_uri, Some(t), Some(json!({})));

    // 無い端末・window の無い端末は 404 (発行しない)
    assert_eq!(
        call(
            &app,
            "POST",
            "/api/devices/re-pair",
            None,
            Some(re_pair(Uuid::new_v4(), None))
        )
        .await
        .status,
        404
    );
    assert_eq!(
        call(
            &app,
            "POST",
            "/api/devices/re-pair",
            None,
            Some(re_pair(id, Some("hw-1")))
        )
        .await
        .status,
        404
    );
    assert!(pairer.calls.lock().unwrap().is_empty());

    assert_eq!(authorize().await.status, 200);
    let got = call(
        &app,
        "POST",
        "/api/devices/re-pair",
        None,
        Some(re_pair(id, Some("hw-1"))),
    )
    .await;
    assert_eq!(got.status, 200);
    assert_eq!(got.headers.get("cache-control").unwrap(), "no-store");
    assert_eq!(
        got.json(),
        json!({ "auth_device_id": "auth-dev-1", "device_secret": "secret-1" })
    );
    assert_eq!(
        *pairer.calls.lock().unwrap(),
        vec![(id, format!("{LABEL_PREFIX}{id}"))]
    );
    assert_eq!(row(id).await, (false, 1, true, Some("hw-1".to_owned())));

    // window を開け直しても、cooldown の間は 429
    assert_eq!(authorize().await.status, 200);
    assert_eq!(
        call(
            &app,
            "POST",
            "/api/devices/re-pair",
            None,
            Some(re_pair(id, Some("hw-1")))
        )
        .await
        .status,
        429
    );
    // cooldown が過ぎても、結び付いた hardware と違えば 404
    admin()
        .await
        .execute("UPDATE alc_api.devices SET last_re_pair_at = now() - interval '11 minutes' WHERE id = $1", &[&id])
        .await
        .unwrap();
    assert_eq!(
        call(
            &app,
            "POST",
            "/api/devices/re-pair",
            None,
            Some(re_pair(id, Some("hw-2")))
        )
        .await
        .status,
        404
    );
    let got = call(
        &app,
        "POST",
        "/api/devices/re-pair",
        None,
        Some(re_pair(id, Some("hw-1"))),
    )
    .await;
    assert_eq!(got.status, 200);
    assert_eq!(row(id).await, (false, 2, true, Some("hw-1".to_owned())));

    assert_eq!(
        app.logs(),
        vec![
            "devices: re-pair denied (not_found)".to_owned(),
            "devices: re-pair denied (cooldown)".to_owned(),
            "devices: re-pair denied (not_found)".to_owned(),
        ]
    );
    support::assert_logs_clean(&app, &[id.to_string(), t.to_string()]);
}

/// 発行の口が無い・発行に失敗・window が先に消費された は 404 (window は残る / 消費されない)
#[tokio::test]
async fn re_pair_fails_closed() {
    let t = tenant().await;
    let id = device(t, "active", None).await;
    admin()
        .await
        .execute(
            "UPDATE alc_api.devices SET re_pair_authorized_until = now() + interval '10 minutes' WHERE id = $1",
            &[&id],
        )
        .await
        .unwrap();

    let no_pairer = build(rt_client().await);
    assert_eq!(
        call(
            &no_pairer,
            "POST",
            "/api/devices/re-pair",
            None,
            Some(re_pair(id, None))
        )
        .await
        .status,
        404
    );
    assert_eq!(
        no_pairer.logs(),
        vec!["devices: re-pair pairer not configured".to_owned()]
    );

    let failing = build_with(
        rt_client().await,
        Some(Arc::new(FakePairer::new(false)) as SharedPairer),
    );
    assert_eq!(
        call(
            &failing,
            "POST",
            "/api/devices/re-pair",
            None,
            Some(re_pair(id, None))
        )
        .await
        .status,
        404
    );
    assert_eq!(
        failing.logs(),
        vec!["devices: re-pair pair failed".to_owned()]
    );
    assert_eq!(row(id).await, (true, 0, false, None));

    // 発行の間に別の要求が window を消費した (読んだ window と違う) → 記録せず 404
    let mut racing = FakePairer::new(true);
    racing.before = Some(Box::new(|device| {
        Box::pin(async move {
            admin()
                .await
                .execute(
                    "UPDATE alc_api.devices SET re_pair_authorized_until = NULL WHERE id = $1",
                    &[&device],
                )
                .await
                .unwrap();
        })
    }));
    let raced = build_with(rt_client().await, Some(Arc::new(racing) as SharedPairer));
    assert_eq!(
        call(
            &raced,
            "POST",
            "/api/devices/re-pair",
            None,
            Some(re_pair(id, None))
        )
        .await
        .status,
        404
    );
    assert_eq!(
        raced.logs(),
        vec!["devices: re-pair denied (window already consumed)".to_owned()]
    );
    assert_eq!(row(id).await, (false, 0, false, None));
}

/// DB の失敗は 500 (段の名前と kind だけをログに)
#[tokio::test]
async fn db_failures_are_500_with_fixed_logs() {
    let t = tenant().await;
    let id = device(t, "active", None).await;
    let broken = build_with(
        broken_client().await,
        Some(Arc::new(FakePairer::new(true)) as SharedPairer),
    );
    let got = call(
        &broken,
        "POST",
        &format!("/api/devices/{id}/authorize-repair"),
        Some(t),
        Some(json!({})),
    )
    .await;
    assert_eq!(got.status, 500);
    assert_eq!(
        call(
            &broken,
            "POST",
            "/api/devices/re-pair",
            None,
            Some(re_pair(id, None))
        )
        .await
        .status,
        500
    );
    for stage in ["authorize-repair", "re-pair lookup"] {
        assert!(
            broken
                .logs()
                .iter()
                .any(|l| l.starts_with(&format!("devices: {stage} failed: db ("))),
            "{stage}"
        );
    }

    // 発行の後に接続が切れた → 記録できず 500
    admin()
        .await
        .execute(
            "UPDATE alc_api.devices SET re_pair_authorized_until = now() + interval '10 minutes' WHERE id = $1",
            &[&id],
        )
        .await
        .unwrap();
    let mut pg = rt_client().await;
    let pid = backend_pid(&mut pg).await;
    let mut cutting = FakePairer::new(true);
    cutting.before = Some(Box::new(move |_| Box::pin(terminate(pid))));
    let app = build_with(pg, Some(Arc::new(cutting) as SharedPairer));
    assert_eq!(
        call(
            &app,
            "POST",
            "/api/devices/re-pair",
            None,
            Some(re_pair(id, None))
        )
        .await
        .status,
        500
    );
    assert!(app
        .logs()
        .iter()
        .any(|l| l.starts_with("devices: re-pair record failed: db (")));
    support::assert_logs_clean(&app, &[id.to_string(), t.to_string()]);
}
