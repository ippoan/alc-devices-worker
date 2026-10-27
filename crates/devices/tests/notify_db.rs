//! FCM で端末に送る口 (W6b-c) と着信の設定の通知を実 DB で通す (rust-alc-api の devices の FCM の 7 口の要点)。
//! 送信は偽物を差す。接続は本番の worker と同じ実行用ロール `alc_api_rt` (RLS が効く)。
//!
//! 全テナントを横断する口 (`fcm-notify-call`・`test-fcm-all-exclude`・`trigger-update-dev`) は、同じ DB に並行して
//! 端末を作るほかのテストの行も拾う。件数は比べず、このテストが作った端末 (token は乱数) に何が送られたかで確かめる。

mod support;

use std::sync::{Arc, Mutex as StdMutex};

use devices::fcm::{Data, FcmError, FcmSend, SharedFcm};
use futures_util::future::BoxFuture;
use serde_json::{json, Value};
use support::{admin, broken_client, build_full, call_with, rt_client, tenant, App, NOW_MS};
use uuid::Uuid;

const SECRET: &str = "test-internal-secret";

/// 偽の送信。送った (token, data) を覚え、token が `bad-` で始まれば失敗する
#[derive(Default)]
struct FakeFcm {
    sent: StdMutex<Vec<(String, Data)>>,
}

impl FcmSend for FakeFcm {
    fn send<'a>(&'a self, token: &'a str, data: Data) -> BoxFuture<'a, Result<(), FcmError>> {
        self.sent.lock().unwrap().push((token.to_owned(), data));
        let result = if token.starts_with("bad-") {
            Err(FcmError::Send("FCM API returned 404".to_owned()))
        } else {
            Ok(())
        };
        Box::pin(async move { result })
    }
}

impl FakeFcm {
    /// `token` に送った data
    fn to(&self, token: &str) -> Vec<Data> {
        self.sent
            .lock()
            .unwrap()
            .iter()
            .filter(|(t, _)| t == token)
            .map(|(_, d)| d.clone())
            .collect()
    }
}

async fn app_with(fcm: Option<Arc<FakeFcm>>, secret: Option<&str>) -> App {
    build_full(rt_client().await, None, fcm.map(|f| f as SharedFcm), secret)
}

/// 端末の行の作り方
struct Dev<'a> {
    name: &'a str,
    status: &'a str,
    token: Option<String>,
    call_enabled: bool,
    schedule: Option<Value>,
    is_dev: bool,
    version: Option<i32>,
}

impl Default for Dev<'_> {
    fn default() -> Self {
        Self {
            name: "端末",
            status: "active",
            token: None,
            call_enabled: true,
            schedule: None,
            is_dev: false,
            version: None,
        }
    }
}

/// 乱数の token
fn tok(prefix: &str) -> String {
    format!("{prefix}{}", Uuid::new_v4())
}

async fn device(tenant: Uuid, d: Dev<'_>) -> Uuid {
    admin()
        .await
        .query_one(
            "INSERT INTO alc_api.devices (tenant_id, device_name, status, fcm_token, call_enabled, call_schedule, \
             is_dev_device, app_version_code) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id",
            &[
                &tenant, &d.name, &d.status, &d.token, &d.call_enabled, &d.schedule, &d.is_dev, &d.version,
            ],
        )
        .await
        .unwrap()
        .get(0)
}

async fn post(
    app: &App,
    uri: &str,
    tenant: Option<Uuid>,
    secret: Option<&str>,
    body: Value,
) -> support::Got {
    let headers: Vec<(&str, &str)> = secret
        .map(|s| vec![("X-Internal-Secret", s)])
        .unwrap_or_default();
    call_with(app, "POST", uri, tenant, &headers, Some(body)).await
}

fn ts() -> String {
    NOW_MS.to_string()
}

/// 内部の 3 口: 設定が無ければ 503・違えば 401。FCM が無ければ 503 (OTA の dev だけは 0 件の 200 = rust と同じ)
#[tokio::test]
async fn internal_secret_and_missing_fcm() {
    let t = tenant().await;
    device(
        t,
        Dev {
            token: Some(tok("dev-")),
            is_dev: true,
            ..Dev::default()
        },
    )
    .await;
    let uris = [
        "/api/devices/fcm-notify-call",
        "/api/devices/test-fcm-all-exclude",
        "/api/devices/trigger-update-dev",
    ];
    let body = json!({ "room_ids": ["r1"] });
    let fcm = Arc::new(FakeFcm::default());
    let no_secret = app_with(Some(fcm.clone()), None).await;
    let with_secret = app_with(Some(fcm.clone()), Some(SECRET)).await;
    for uri in uris {
        assert_eq!(
            post(&no_secret, uri, None, Some(SECRET), body.clone())
                .await
                .status,
            503,
            "{uri}"
        );
        assert_eq!(
            post(&with_secret, uri, None, None, body.clone())
                .await
                .status,
            401,
            "{uri}"
        );
        assert_eq!(
            post(&with_secret, uri, None, Some("other"), body.clone())
                .await
                .status,
            401,
            "{uri}"
        );
    }
    assert!(fcm.sent.lock().unwrap().is_empty());

    let no_fcm = app_with(None, Some(SECRET)).await;
    for uri in &uris[..2] {
        assert_eq!(
            post(&no_fcm, uri, None, Some(SECRET), body.clone())
                .await
                .status,
            503,
            "{uri}"
        );
    }
    let got = post(&no_fcm, uris[2], None, Some(SECRET), json!({})).await;
    assert_eq!(got.status, 200);
    assert_eq!(
        got.json(),
        json!({ "sent": 0, "skipped": 0, "already_updated": 0, "errors": 0, "results": [] })
    );
    // 管理画面・端末の口も FCM が無ければ 503
    let d = device(
        t,
        Dev {
            token: Some(tok("t-")),
            ..Dev::default()
        },
    )
    .await;
    for (uri, tenant_id, b) in [
        (format!("/api/devices/{d}/test-fcm"), Some(t), json!({})),
        ("/api/devices/test-fcm-all".to_owned(), Some(t), json!({})),
        ("/api/devices/trigger-update".to_owned(), Some(t), json!({})),
        (
            "/api/devices/fcm-dismiss-test".to_owned(),
            None,
            json!({ "device_id": d }),
        ),
    ] {
        assert_eq!(
            post(&no_fcm, &uri, tenant_id, None, b).await.status,
            503,
            "{uri}"
        );
    }
}

/// 着信の通知: 除く端末・着信を受けない設定・時間帯の外は飛ばす。送れなければ errors。data は rust と同じ
#[tokio::test]
async fn notify_call_sends_to_callable_devices() {
    let t = tenant().await;
    let fcm = Arc::new(FakeFcm::default());
    let app = app_with(Some(fcm.clone()), Some(SECRET)).await;
    let (ok, bad, off, out, excluded, disabled) = (
        tok("ok-"),
        tok("bad-"),
        tok("off-"),
        tok("out-"),
        tok("ex-"),
        tok("dis-"),
    );
    device(
        t,
        Dev {
            token: Some(ok.clone()),
            ..Dev::default()
        },
    )
    .await;
    device(
        t,
        Dev {
            token: Some(bad.clone()),
            ..Dev::default()
        },
    )
    .await;
    device(
        t,
        Dev {
            token: Some(off.clone()),
            call_enabled: false,
            ..Dev::default()
        },
    )
    .await;
    // テストの今は水曜 10:30 JST
    device(
        t,
        Dev {
            token: Some(out.clone()),
            schedule: Some(json!({ "days": [0] })),
            ..Dev::default()
        },
    )
    .await;
    let ex = device(
        t,
        Dev {
            token: Some(excluded.clone()),
            ..Dev::default()
        },
    )
    .await;
    device(
        t,
        Dev {
            token: Some(disabled.clone()),
            status: "disabled",
            ..Dev::default()
        },
    )
    .await;

    // room_ids が空なら何も送らない
    let got = post(
        &app,
        "/api/devices/fcm-notify-call",
        None,
        Some(SECRET),
        json!({ "room_ids": [] }),
    )
    .await;
    assert_eq!(
        (got.status, got.json()),
        (200, json!({ "sent": 0, "skipped": 0, "errors": 0 }))
    );
    assert!(fcm.sent.lock().unwrap().is_empty());

    let body = json!({ "room_ids": ["r1", "r2"], "exclude_device_ids": [ex.to_string()] });
    let got = post(
        &app,
        "/api/devices/fcm-notify-call",
        None,
        Some(SECRET),
        body,
    )
    .await;
    assert_eq!(got.status, 200);
    let r = got.json();
    assert!(
        r["sent"].as_u64().unwrap() >= 1
            && r["errors"].as_u64().unwrap() >= 1
            && r["skipped"].as_u64().unwrap() >= 3
    );
    let want = Data::from([
        ("type".to_owned(), "incoming_call".to_owned()),
        ("room_ids".to_owned(), r#"["r1","r2"]"#.to_owned()),
        ("timestamp".to_owned(), ts()),
    ]);
    assert_eq!(fcm.to(&ok), vec![want.clone()]);
    assert_eq!(fcm.to(&bad), vec![want]);
    for skipped in [&off, &out, &excluded, &disabled] {
        assert!(fcm.to(skipped).is_empty());
    }
    assert!(app
        .logs()
        .iter()
        .any(|l| l.starts_with("devices: fcm notify call sent=")));
    support::assert_logs_clean(&app, &[ok, ex.to_string(), t.to_string()]);
}

/// 試験の送信 (内部): 着信を受ける全端末へ。除く端末は飛ばす。結果は端末ごと (失敗は error の文)
#[tokio::test]
async fn test_fcm_all_exclude_reports_each_device() {
    let t = tenant().await;
    let fcm = Arc::new(FakeFcm::default());
    let app = app_with(Some(fcm.clone()), Some(SECRET)).await;
    let (ok, bad, excluded) = (tok("ok-"), tok("bad-"), tok("ex-"));
    let ok_id = device(
        t,
        Dev {
            name: "受付",
            token: Some(ok.clone()),
            ..Dev::default()
        },
    )
    .await;
    let bad_id = device(
        t,
        Dev {
            name: "倉庫",
            token: Some(bad.clone()),
            ..Dev::default()
        },
    )
    .await;
    let ex = device(
        t,
        Dev {
            token: Some(excluded.clone()),
            ..Dev::default()
        },
    )
    .await;
    let body = json!({ "exclude_device_ids": [ex.to_string()] });
    let got = post(
        &app,
        "/api/devices/test-fcm-all-exclude",
        None,
        Some(SECRET),
        body,
    )
    .await;
    assert_eq!(got.status, 200);
    let r = got.json();
    let results = r["results"].as_array().unwrap();
    let of = |id: Uuid| {
        results
            .iter()
            .find(|x| x["device_id"] == id.to_string())
            .cloned()
    };
    assert_eq!(
        of(ok_id),
        Some(json!({ "device_id": ok_id.to_string(), "device_name": "受付", "success": true }))
    );
    assert_eq!(
        of(bad_id),
        Some(json!({
            "device_id": bad_id.to_string(), "device_name": "倉庫", "success": false,
            "error": "FCM send error: FCM API returned 404",
        }))
    );
    assert_eq!(of(ex), None);
    assert_eq!(
        fcm.to(&ok),
        vec![Data::from([
            ("type".to_owned(), "test".to_owned()),
            ("timestamp".to_owned(), ts())
        ])]
    );
    assert!(fcm.to(&excluded).is_empty());
}

/// 試験の通知を閉じる: 端末のテナントのほかの有効な端末へ。端末が無い・有効でなければ 404
#[tokio::test]
async fn dismiss_goes_to_the_other_devices_of_the_tenant() {
    let t = tenant().await;
    let other_tenant = tenant().await;
    let fcm = Arc::new(FakeFcm::default());
    let app = app_with(Some(fcm.clone()), None).await;
    let (me_tok, peer, bad, disabled, foreign) = (
        tok("me-"),
        tok("peer-"),
        tok("bad-"),
        tok("dis-"),
        tok("fx-"),
    );
    let me = device(
        t,
        Dev {
            token: Some(me_tok.clone()),
            ..Dev::default()
        },
    )
    .await;
    device(
        t,
        Dev {
            token: Some(peer.clone()),
            ..Dev::default()
        },
    )
    .await;
    device(
        t,
        Dev {
            token: Some(bad.clone()),
            ..Dev::default()
        },
    )
    .await;
    device(t, Dev { ..Dev::default() }).await;
    device(
        t,
        Dev {
            token: Some(disabled.clone()),
            status: "disabled",
            ..Dev::default()
        },
    )
    .await;
    device(
        other_tenant,
        Dev {
            token: Some(foreign.clone()),
            ..Dev::default()
        },
    )
    .await;
    let off = device(
        t,
        Dev {
            status: "disabled",
            ..Dev::default()
        },
    )
    .await;

    let got = post(
        &app,
        "/api/devices/fcm-dismiss-test",
        None,
        None,
        json!({ "device_id": me }),
    )
    .await;
    assert_eq!((got.status, got.json()), (200, json!({ "sent": 1 })));
    let want = vec![Data::from([("type".to_owned(), "test_dismiss".to_owned())])];
    assert_eq!(fcm.to(&peer), want);
    assert_eq!(fcm.to(&bad), want);
    for none in [&me_tok, &disabled, &foreign] {
        assert!(fcm.to(none).is_empty());
    }
    for id in [Uuid::new_v4(), off] {
        let got = post(
            &app,
            "/api/devices/fcm-dismiss-test",
            None,
            None,
            json!({ "device_id": id }),
        )
        .await;
        assert_eq!(got.status, 404);
    }
}

/// 管理画面の試験の送信: 1 台 (token が無ければ 400、ほかのテナントなら 404) と、テナントの全端末
#[tokio::test]
async fn admin_test_fcm() {
    let t = tenant().await;
    let other = tenant().await;
    let fcm = Arc::new(FakeFcm::default());
    let app = app_with(Some(fcm.clone()), None).await;
    let (ok, bad) = (tok("ok-"), tok("bad-"));
    let ok_id = device(
        t,
        Dev {
            name: "受付",
            token: Some(ok.clone()),
            ..Dev::default()
        },
    )
    .await;
    let bad_id = device(
        t,
        Dev {
            name: "倉庫",
            token: Some(bad.clone()),
            ..Dev::default()
        },
    )
    .await;
    let no_token = device(t, Dev::default()).await;
    device(
        t,
        Dev {
            token: Some(tok("dis-")),
            status: "disabled",
            ..Dev::default()
        },
    )
    .await;

    let one = |id: Uuid| format!("/api/devices/{id}/test-fcm");
    let got = post(&app, &one(ok_id), Some(t), None, json!({})).await;
    assert_eq!((got.status, got.json()), (200, json!({ "success": true })));
    let got = post(&app, &one(bad_id), Some(t), None, json!({})).await;
    assert_eq!(
        (got.status, got.json()),
        (
            200,
            json!({ "success": false, "error": "FCM send error: FCM API returned 404" })
        )
    );
    assert_eq!(
        post(&app, &one(no_token), Some(t), None, json!({}))
            .await
            .status,
        400
    );
    assert_eq!(
        post(&app, &one(ok_id), Some(other), None, json!({}))
            .await
            .status,
        404
    );

    let got = post(&app, "/api/devices/test-fcm-all", Some(t), None, json!({})).await;
    assert_eq!(got.status, 200);
    let mut results = got.json()["results"].as_array().unwrap().clone();
    results.sort_by_key(|r| r["device_name"].as_str().unwrap().to_owned());
    assert_eq!(got.json()["sent"], 1);
    assert_eq!(got.json()["skipped"], 0);
    assert_eq!(got.json()["errors"], 1);
    assert_eq!(
        Value::from(results),
        json!([
            { "device_id": bad_id, "device_name": "倉庫", "success": false, "error": "FCM send error: FCM API returned 404" },
            { "device_id": ok_id, "device_name": "受付", "success": true },
        ])
    );
    assert_eq!(fcm.to(&ok).len(), 2);
}

/// OTA: 端末の指定・版が新しい端末は送らない・dev だけ。data は版・名前・URL。dev の口は全テナントの dev 端末
#[tokio::test]
async fn trigger_update_and_dev() {
    let t = tenant().await;
    let fcm = Arc::new(FakeFcm::default());
    let app = app_with(Some(fcm.clone()), Some(SECRET)).await;
    let (old, new, dev, other) = (tok("old-"), tok("new-"), tok("dev-"), tok("oth-"));
    let old_id = device(
        t,
        Dev {
            name: "a",
            token: Some(old.clone()),
            version: Some(10),
            ..Dev::default()
        },
    )
    .await;
    let new_id = device(
        t,
        Dev {
            name: "b",
            token: Some(new.clone()),
            version: Some(20),
            ..Dev::default()
        },
    )
    .await;
    let dev_id = device(
        t,
        Dev {
            name: "c",
            token: Some(dev.clone()),
            is_dev: true,
            ..Dev::default()
        },
    )
    .await;
    let other_id = device(
        t,
        Dev {
            name: "d",
            token: Some(other.clone()),
            ..Dev::default()
        },
    )
    .await;

    let body = json!({
        "device_ids": [old_id, new_id, dev_id], "version_code": 20, "version_name": "2.0", "download_url": "https://x.test/a.apk",
    });
    let got = post(&app, "/api/devices/trigger-update", Some(t), None, body).await;
    assert_eq!(got.status, 200);
    let r = got.json();
    assert_eq!(
        (
            r["sent"].clone(),
            r["skipped"].clone(),
            r["already_updated"].clone(),
            r["errors"].clone()
        ),
        (json!(2), json!(1), json!(1), json!(0))
    );
    let new_result = r["results"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["device_id"] == json!(new_id))
        .cloned();
    assert_eq!(
        new_result,
        Some(
            json!({ "device_id": new_id, "device_name": "b", "success": true, "error": "already up-to-date" })
        )
    );
    let want = Data::from([
        ("type".to_owned(), "app_update".to_owned()),
        ("timestamp".to_owned(), ts()),
        ("version_code".to_owned(), "20".to_owned()),
        ("version_name".to_owned(), "2.0".to_owned()),
        ("download_url".to_owned(), "https://x.test/a.apk".to_owned()),
    ]);
    assert_eq!(fcm.to(&old), vec![want.clone()]);
    assert_eq!(fcm.to(&dev), vec![want]);
    assert!(fcm.to(&new).is_empty() && fcm.to(&other).is_empty());

    // dev だけ (body の dev_only)
    let got = post(
        &app,
        "/api/devices/trigger-update",
        Some(t),
        None,
        json!({ "dev_only": true }),
    )
    .await;
    assert_eq!(
        (
            got.json()["sent"].clone(),
            got.json()["results"].as_array().unwrap().len()
        ),
        (json!(1), 1)
    );
    let app_only = Data::from([
        ("type".to_owned(), "app_update".to_owned()),
        ("timestamp".to_owned(), ts()),
    ]);
    assert_eq!(fcm.to(&dev).last(), Some(&app_only));

    // dev の口 (内部): 全テナントの dev 端末だけ
    let got = post(
        &app,
        "/api/devices/trigger-update-dev",
        None,
        Some(SECRET),
        json!({}),
    )
    .await;
    assert_eq!(got.status, 200);
    let results = got.json()["results"].as_array().unwrap().clone();
    assert!(results.iter().any(|x| x["device_id"] == json!(dev_id)));
    assert!(!results.iter().any(|x| x["device_id"] == json!(other_id)));
    assert_eq!(fcm.to(&dev).len(), 3);
    assert!(fcm.to(&other).is_empty());
}

/// 着信の設定: always_on・bp_enabled が変わったときだけ端末に settings_changed を送る。送れなくても 204
#[tokio::test]
async fn call_settings_notifies_the_device() {
    let t = tenant().await;
    let fcm = Arc::new(FakeFcm::default());
    let app = app_with(Some(fcm.clone()), None).await;
    let (ok, bad) = (tok("ok-"), tok("bad-"));
    let ok_id = device(
        t,
        Dev {
            token: Some(ok.clone()),
            ..Dev::default()
        },
    )
    .await;
    let bad_id = device(
        t,
        Dev {
            token: Some(bad.clone()),
            ..Dev::default()
        },
    )
    .await;
    let no_token = device(t, Dev::default()).await;
    let put = |id: Uuid, body: Value| {
        let app = &app;
        async move {
            call_with(
                app,
                "PUT",
                &format!("/api/devices/{id}/call-settings"),
                Some(t),
                &[],
                Some(body),
            )
            .await
            .status
        }
    };
    assert_eq!(put(ok_id, json!({ "call_enabled": true })).await, 204);
    assert!(fcm.to(&ok).is_empty());
    assert_eq!(
        put(ok_id, json!({ "call_enabled": true, "always_on": true })).await,
        204
    );
    assert_eq!(
        put(ok_id, json!({ "call_enabled": false, "bp_enabled": false })).await,
        204
    );
    let want = Data::from([
        ("type".to_owned(), "settings_changed".to_owned()),
        ("timestamp".to_owned(), ts()),
    ]);
    assert_eq!(fcm.to(&ok), vec![want.clone(), want]);
    assert_eq!(
        put(
            no_token,
            json!({ "call_enabled": true, "always_on": false })
        )
        .await,
        204
    );
    assert_eq!(
        put(bad_id, json!({ "call_enabled": true, "always_on": false })).await,
        204
    );
    assert_eq!(
        app.logs(),
        vec!["devices: settings_changed fcm failed".to_owned()]
    );
    // FCM が無くても 204 (送らない)
    let no_fcm = app_with(None, None).await;
    let got = call_with(
        &no_fcm,
        "PUT",
        &format!("/api/devices/{ok_id}/call-settings"),
        Some(t),
        &[],
        Some(json!({ "call_enabled": true, "always_on": true })),
    )
    .await;
    assert_eq!(got.status, 204);
    assert_eq!(fcm.to(&ok).len(), 2);
}

/// (uri, テナント, X-Internal-Secret, 本文, ログの段の名前)
type Case = (
    String,
    Option<Uuid>,
    Option<&'static str>,
    Value,
    &'static str,
);

#[tokio::test]
async fn db_failures_are_500_with_fixed_logs() {
    let fcm = Arc::new(FakeFcm::default());
    let app = build_full(
        broken_client().await,
        None,
        Some(fcm as SharedFcm),
        Some(SECRET),
    );
    let t = Uuid::new_v4();
    let id = Uuid::new_v4();
    let cases: Vec<Case> = vec![
        (
            "/api/devices/fcm-notify-call".into(),
            None,
            Some(SECRET),
            json!({ "room_ids": ["r"] }),
            "fcm notify call",
        ),
        (
            "/api/devices/fcm-dismiss-test".into(),
            None,
            None,
            json!({ "device_id": id }),
            "fcm dismiss test",
        ),
        (
            "/api/devices/test-fcm-all-exclude".into(),
            None,
            Some(SECRET),
            json!({}),
            "test fcm all exclude",
        ),
        (
            "/api/devices/trigger-update-dev".into(),
            None,
            Some(SECRET),
            json!({}),
            "trigger update dev",
        ),
        (
            format!("/api/devices/{id}/test-fcm"),
            Some(t),
            None,
            json!({}),
            "test fcm",
        ),
        (
            "/api/devices/test-fcm-all".into(),
            Some(t),
            None,
            json!({}),
            "test fcm all",
        ),
        (
            "/api/devices/trigger-update".into(),
            Some(t),
            None,
            json!({}),
            "trigger update",
        ),
    ];
    for (uri, tenant_id, secret, body, stage) in cases {
        let got = post(&app, &uri, tenant_id, secret, body).await;
        assert_eq!(got.status, 500, "{stage}");
        assert!(
            app.logs()
                .iter()
                .any(|l| l.starts_with(&format!("devices: {stage} failed: db ("))),
            "{stage} のログ"
        );
    }
    support::assert_logs_clean(&app, &[id.to_string(), t.to_string()]);
}
