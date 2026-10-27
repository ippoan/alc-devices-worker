//! 管理画面の口を実 DB で通す (rust-alc-api の tests/devices_test.rs・mock の devices の要点を写したもの)。
//! 接続は本番の worker と同じ実行用ロール `alc_api_rt` (RLS が効く)。

mod support;

use serde_json::{json, Value};
use support::{admin, broken_client, build, call, call_with, tenant};
use uuid::Uuid;

/// 管理者を 1 人作る (承認者の FK 用)
async fn user(tenant: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    admin()
        .await
        .execute(
            "INSERT INTO alc_api.users (id, tenant_id, google_sub, email, name) VALUES ($1, $2, $3, 'a@example.invalid', '管理 一郎')",
            &[&id, &tenant, &format!("sub-{id}")],
        )
        .await
        .unwrap();
    id
}

/// 承認者のヘッダ (auth-worker が付ける)
fn as_user(user: Uuid) -> Vec<(String, String)> {
    vec![
        ("X-User-ID".into(), user.to_string()),
        ("X-User-Email".into(), "a@example.invalid".into()),
        ("X-User-Role".into(), "admin".into()),
    ]
}

async fn call_as(
    app: &support::App,
    method: &str,
    uri: &str,
    t: Uuid,
    headers: &[(String, String)],
    body: Option<Value>,
) -> support::Got {
    let h: Vec<(&str, &str)> = headers
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    call_with(app, method, uri, Some(t), &h, body).await
}

/// 登録の行 (superuser で。flow_type・テナント・期限を選ぶ)
async fn registration(
    code: &str,
    flow: &str,
    tenant: Option<Uuid>,
    phone: Option<&str>,
    expires: &str,
    owner: bool,
    dev: bool,
) -> Uuid {
    admin()
        .await
        .query_one(
            &format!(
                "INSERT INTO alc_api.device_registration_requests \
                 (registration_code, flow_type, tenant_id, phone_number, device_name, expires_at, is_device_owner, is_dev_device) \
                 VALUES ($1, $2, $3, $4, '登録の名前', {expires}, $5, $6) RETURNING id"
            ),
            &[&code, &flow, &tenant, &phone, &owner, &dev],
        )
        .await
        .unwrap()
        .get(0)
}

async fn request_row(id: Uuid) -> (String, Option<Uuid>, Option<Uuid>) {
    let r = admin()
        .await
        .query_one(
            "SELECT status, tenant_id, device_id FROM alc_api.device_registration_requests WHERE id = $1",
            &[&id],
        )
        .await
        .unwrap();
    (r.get(0), r.get(1), r.get(2))
}

#[tokio::test]
async fn tenant_header_is_required() {
    let app = support::app().await;
    for (method, uri) in [
        ("GET", "/api/devices"),
        ("GET", "/api/devices/pending"),
        ("POST", "/api/devices/register/create-token"),
    ] {
        assert_eq!(
            call(&app, method, uri, None, Some(json!({}))).await.status,
            401,
            "{uri}"
        );
    }
}

/// コードの発行: URL (24 時間・URL 付き)・QR 永久・Device Owner (常に Device Owner)。承認待ちの一覧に出る
#[tokio::test]
async fn issue_codes_and_list_pending() {
    let app = support::app().await;
    let t = tenant().await;
    let other = tenant().await;
    let url = call(
        &app,
        "POST",
        "/api/devices/register/create-token",
        Some(t),
        Some(json!({ "device_name": "受付", "is_dev_device": true })),
    )
    .await;
    assert_eq!(url.status, 200);
    let url = url.json();
    let code = url["registration_code"].as_str().unwrap().to_owned();
    assert!(Uuid::parse_str(&code).is_ok());
    assert_eq!(
        url["registration_url"],
        format!("/device-claim?token={code}")
    );

    let qr = call(
        &app,
        "POST",
        "/api/devices/register/create-permanent-qr",
        Some(t),
        Some(json!({ "is_device_owner": true })),
    )
    .await;
    let do_ = call(
        &app,
        "POST",
        "/api/devices/register/create-device-owner-token",
        Some(t),
        Some(json!({ "is_device_owner": false })),
    )
    .await;
    assert_eq!((qr.status, do_.status), (200, 200));
    assert_eq!(qr.json().as_object().unwrap().len(), 1);

    // 期限切れ・他テナント・承認済みは出ない。テナント未定 (QR 一時) は出る
    registration(
        &format!("old-{t}"),
        "url",
        Some(t),
        None,
        "NOW() - INTERVAL '1 hour'",
        false,
        false,
    )
    .await;
    registration(
        &format!("other-{t}"),
        "url",
        Some(other),
        None,
        "NULL",
        false,
        false,
    )
    .await;
    let temp = registration(
        &format!("temp-{t}"),
        "qr_temp",
        None,
        None,
        "NOW() + INTERVAL '10 minutes'",
        false,
        false,
    )
    .await;

    let pending = call(&app, "GET", "/api/devices/pending", Some(t), None)
        .await
        .json();
    let rows = pending.as_array().unwrap();
    let flows: Vec<(&str, bool, bool, &str)> = rows
        .iter()
        .map(|r| {
            (
                r["flow_type"].as_str().unwrap(),
                r["is_device_owner"].as_bool().unwrap(),
                r["is_dev_device"].as_bool().unwrap(),
                r["device_name"].as_str().unwrap(),
            )
        })
        .collect();
    assert!(flows.contains(&("url", false, true, "受付")));
    assert!(flows.contains(&("qr_permanent", true, false, "")));
    assert!(flows.contains(&("device_owner", true, false, "")));
    assert!(rows
        .iter()
        .any(|r| r["id"] == json!(temp) && r["tenant_id"].is_null()));
    // 期限切れ・他テナントは出ない (テナント未定の行は並列のテストのものも出るので、自分のテナントの行だけ数える)
    assert_eq!(
        rows.iter().filter(|r| r["tenant_id"] == json!(t)).count(),
        3
    );
    assert!(rows
        .iter()
        .all(|r| r["status"] == "pending" && r["created_at"].is_string()));
}

/// 承認 (ID・コード): 端末を作り、登録を approved に (テナント未定は承認者のテナントに)。
/// 他テナントの登録・承認済み・期限切れは 404。承認者はヘッダから
#[tokio::test]
async fn approve_by_id_and_code() {
    let app = support::app().await;
    let t = tenant().await;
    let other = tenant().await;
    let approver = user(t).await;
    let h = as_user(approver);

    let req = registration(
        &format!("perm-{t}"),
        "qr_permanent",
        Some(t),
        Some("09000000000"),
        "NULL",
        true,
        false,
    )
    .await;
    let got = call_as(
        &app,
        "POST",
        &format!("/api/devices/approve/{req}"),
        t,
        &h,
        Some(json!({ "device_name": "上書き" })),
    )
    .await;
    assert_eq!(got.status, 200);
    let body = got.json();
    assert_eq!(
        (body["success"].clone(), body["tenant_id"].clone()),
        (json!(true), json!(t))
    );
    let device_id: Uuid = serde_json::from_value(body["device_id"].clone()).unwrap();
    assert_eq!(
        request_row(req).await,
        ("approved".into(), Some(t), Some(device_id))
    );
    let d = admin()
        .await
        .query_one(
            "SELECT device_name, device_type, phone_number, approved_by, is_device_owner, settings_token IS NOT NULL FROM alc_api.devices WHERE id = $1",
            &[&device_id],
        )
        .await
        .unwrap();
    assert_eq!(d.get::<_, String>(0), "上書き");
    assert_eq!(d.get::<_, String>(1), "android");
    assert_eq!(
        d.get::<_, Option<String>>(2).as_deref(),
        Some("09000000000")
    );
    assert_eq!(d.get::<_, Option<Uuid>>(3), Some(approver));
    assert!(d.get::<_, bool>(4) && d.get::<_, bool>(5));
    // 承認済みはもう引けない
    assert_eq!(
        call(
            &app,
            "POST",
            &format!("/api/devices/approve/{req}"),
            Some(t),
            Some(json!({}))
        )
        .await
        .status,
        404
    );

    // コード: テナント未定 (QR 一時) を承認者のテナントで。名前は登録のもの、承認者の無い要求も通る
    let code = format!("temp-{t}");
    let temp = registration(
        &code,
        "qr_temp",
        None,
        None,
        "NOW() + INTERVAL '10 minutes'",
        false,
        true,
    )
    .await;
    let got = call(
        &app,
        "POST",
        &format!("/api/devices/approve-by-code/{code}"),
        Some(t),
        None,
    )
    .await;
    assert_eq!(got.status, 200);
    let (status, tenant_id, device) = request_row(temp).await;
    assert_eq!((status.as_str(), tenant_id), ("approved", Some(t)));
    let kiosk = admin()
        .await
        .query_one(
            "SELECT device_name, device_type, approved_by, is_dev_device FROM alc_api.devices WHERE id = $1",
            &[&device.unwrap()],
        )
        .await
        .unwrap();
    assert_eq!(
        (
            kiosk.get::<_, String>(0),
            kiosk.get::<_, String>(1),
            kiosk.get::<_, Option<Uuid>>(2),
            kiosk.get::<_, bool>(3)
        ),
        ("登録の名前".into(), "kiosk".into(), None, true)
    );

    // 404: 他テナントの登録 (ID・コード)・期限切れのコード・無いコード。コードの外れはログに残す (識別子なし)
    let foreign = registration(
        &format!("foreign-{t}"),
        "qr_permanent",
        Some(other),
        None,
        "NULL",
        false,
        false,
    )
    .await;
    assert_eq!(
        call(
            &app,
            "POST",
            &format!("/api/devices/approve/{foreign}"),
            Some(t),
            Some(json!({}))
        )
        .await
        .status,
        404
    );
    registration(
        &format!("expired-{t}"),
        "qr_temp",
        None,
        None,
        "NOW() - INTERVAL '1 minute'",
        false,
        false,
    )
    .await;
    for c in [
        format!("foreign-{t}"),
        format!("expired-{t}"),
        "nothing".to_owned(),
    ] {
        assert_eq!(
            call(
                &app,
                "POST",
                &format!("/api/devices/approve-by-code/{c}"),
                Some(t),
                None
            )
            .await
            .status,
            404
        );
    }
    assert_eq!(request_row(foreign).await.0, "pending");
    assert_eq!(
        app.logs(),
        vec!["devices: approve-by-code miss".to_owned(); 3]
    );
    support::assert_logs_clean(&app, &[t.to_string(), "foreign".into(), "expired".into()]);
}

/// 一覧・却下・停止・再開・削除・着信の設定。他テナントの端末には届かない
#[tokio::test]
async fn manage_devices() {
    let app = support::app().await;
    let t = tenant().await;
    let other = tenant().await;
    let mut ids = Vec::new();
    for (i, tn) in [t, t, other].into_iter().enumerate() {
        let req = registration(
            &format!("m{i}-{t}"),
            "qr_permanent",
            Some(tn),
            None,
            "NULL",
            false,
            false,
        )
        .await;
        let got = call(
            &app,
            "POST",
            &format!("/api/devices/approve/{req}"),
            Some(tn),
            Some(json!({})),
        )
        .await;
        ids.push(serde_json::from_value::<Uuid>(got.json()["device_id"].clone()).unwrap());
    }
    let (a, b, foreign) = (ids[0], ids[1], ids[2]);

    let list = call(&app, "GET", "/api/devices", Some(t), None)
        .await
        .json();
    let rows = list.as_array().unwrap();
    assert_eq!(
        rows.iter().map(|r| r["id"].clone()).collect::<Vec<_>>(),
        vec![json!(b), json!(a)]
    );
    let r = &rows[0];
    assert_eq!(r.as_object().unwrap().len(), 29);
    assert_eq!(
        (
            r["status"].clone(),
            r["device_type"].clone(),
            r["re_pair_count"].clone()
        ),
        (json!("active"), json!("kiosk"), json!(0))
    );
    assert!(
        r["approved_at"].is_string() && r["created_at"].is_string() && r["last_seen_at"].is_null()
    );
    assert_eq!(
        (
            r["call_enabled"].clone(),
            r["always_on"].clone(),
            r["bp_enabled"].clone()
        ),
        (json!(false), json!(true), json!(false))
    );

    // 停止 → 二度目は 404 → 再開 → 二度目は 404
    let post = |path: String| {
        let app = &app;
        async move { call(app, "POST", &path, Some(t), None).await.status }
    };
    assert_eq!(post(format!("/api/devices/disable/{a}")).await, 204);
    assert_eq!(post(format!("/api/devices/disable/{a}")).await, 404);
    assert_eq!(post(format!("/api/devices/enable/{a}")).await, 204);
    assert_eq!(post(format!("/api/devices/enable/{a}")).await, 404);
    assert_eq!(post(format!("/api/devices/disable/{foreign}")).await, 404);

    // 却下 (承認待ちだけ。テナント未定も却下できる)
    let pending = registration(
        &format!("rej-{t}"),
        "qr_permanent",
        Some(t),
        None,
        "NULL",
        false,
        false,
    )
    .await;
    let temp = registration(
        &format!("rejtemp-{t}"),
        "qr_temp",
        None,
        None,
        "NOW() + INTERVAL '10 minutes'",
        false,
        false,
    )
    .await;
    let foreign_req = registration(
        &format!("rejforeign-{t}"),
        "qr_permanent",
        Some(other),
        None,
        "NULL",
        false,
        false,
    )
    .await;
    assert_eq!(post(format!("/api/devices/reject/{pending}")).await, 204);
    assert_eq!(post(format!("/api/devices/reject/{pending}")).await, 404);
    assert_eq!(post(format!("/api/devices/reject/{temp}")).await, 204);
    assert_eq!(
        post(format!("/api/devices/reject/{foreign_req}")).await,
        404
    );
    assert_eq!(request_row(pending).await.0, "rejected");
    assert_eq!(request_row(foreign_req).await.0, "pending");

    // 着信の設定 (always_on・bp_enabled は null なら変えない)
    let put = |id: Uuid, body: Value| {
        let app = &app;
        async move {
            call(
                app,
                "PUT",
                &format!("/api/devices/{id}/call-settings"),
                Some(t),
                Some(body),
            )
            .await
            .status
        }
    };
    let schedule = json!({ "mon": ["08:00", "17:00"] });
    assert_eq!(
        put(
            a,
            json!({ "call_enabled": true, "call_schedule": schedule, "bp_enabled": true })
        )
        .await,
        204
    );
    assert_eq!(
        put(
            a,
            json!({ "call_enabled": true, "call_schedule": schedule, "always_on": false })
        )
        .await,
        204
    );
    assert_eq!(put(foreign, json!({ "call_enabled": true })).await, 404);
    let r = admin()
        .await
        .query_one("SELECT call_enabled, call_schedule, always_on, bp_enabled FROM alc_api.devices WHERE id = $1", &[&a])
        .await
        .unwrap();
    assert_eq!(
        (
            r.get::<_, bool>(0),
            r.get::<_, Option<Value>>(1),
            r.get::<_, bool>(2),
            r.get::<_, bool>(3)
        ),
        (true, Some(schedule), false, true)
    );

    // 削除
    let del = |id: Uuid| {
        let app = &app;
        async move {
            call(app, "DELETE", &format!("/api/devices/{id}"), Some(t), None)
                .await
                .status
        }
    };
    assert_eq!(del(b).await, 204);
    assert_eq!(del(b).await, 404);
    assert_eq!(del(foreign).await, 404);
    assert!(app.logs().is_empty());
}

#[tokio::test]
async fn db_failures_are_500_with_fixed_logs() {
    let app = build(broken_client().await);
    let t = Uuid::new_v4();
    let id = Uuid::new_v4();
    let cases: Vec<(&str, String, Option<Value>, &str)> = vec![
        ("GET", "/api/devices".into(), None, "list"),
        ("GET", "/api/devices/pending".into(), None, "pending"),
        (
            "POST",
            "/api/devices/register/create-token".into(),
            Some(json!({})),
            "create token",
        ),
        (
            "POST",
            format!("/api/devices/approve/{id}"),
            Some(json!({})),
            "approve lookup",
        ),
        ("POST", format!("/api/devices/reject/{id}"), None, "reject"),
        (
            "POST",
            format!("/api/devices/disable/{id}"),
            None,
            "disable",
        ),
        ("POST", format!("/api/devices/enable/{id}"), None, "enable"),
        ("DELETE", format!("/api/devices/{id}"), None, "delete"),
        (
            "PUT",
            format!("/api/devices/{id}/call-settings"),
            Some(json!({ "call_enabled": true })),
            "call settings",
        ),
    ];
    for (method, uri, body, stage) in cases {
        let got = call(&app, method, &uri, Some(t), body).await;
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

/// 承認の対象は引けたが、端末を作れない (読み取りだけのロール) → 500
#[tokio::test]
async fn approve_write_failure_is_500() {
    let app = build(support::client_as(support::READ_ONLY_ROLE).await);
    let t = tenant().await;
    let req = registration(
        &format!("ro-{t}"),
        "qr_permanent",
        Some(t),
        None,
        "NULL",
        false,
        false,
    )
    .await;
    let got = call(
        &app,
        "POST",
        &format!("/api/devices/approve/{req}"),
        Some(t),
        Some(json!({})),
    )
    .await;
    assert_eq!(got.status, 500);
    assert!(app
        .logs()
        .iter()
        .any(|l| l.starts_with("devices: approve failed: db (")));
}
