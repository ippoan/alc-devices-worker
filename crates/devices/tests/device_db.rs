//! 端末の口と内部の口を実 DB で通す (テナントのヘッダ無し。テナントは端末の ID から引く)。
//! 接続は本番の worker と同じ実行用ロール `alc_api_rt` (RLS が効く)。

mod support;

use serde_json::{json, Value};
use support::{admin, broken_client, build, call, call_with, employee, tenant};
use uuid::Uuid;

/// 登録の行 (superuser で)
async fn registration(
    code: &str,
    flow: &str,
    tenant: Option<Uuid>,
    status: &str,
    expires: &str,
    owner: bool,
) -> Uuid {
    admin()
        .await
        .query_one(
            &format!(
                "INSERT INTO alc_api.device_registration_requests \
                 (registration_code, flow_type, tenant_id, device_name, status, expires_at, is_device_owner, is_dev_device) \
                 VALUES ($1, $2, $3, '管理者の名前', $4, {expires}, $5, true) RETURNING id"
            ),
            &[&code, &flow, &tenant, &status, &owner],
        )
        .await
        .unwrap()
        .get(0)
}

/// 端末の行 (superuser で)。settings_token を付けるか選ぶ
async fn device(tenant: Uuid, status: &str, token: Option<Uuid>) -> Uuid {
    admin()
        .await
        .query_one(
            "INSERT INTO alc_api.devices (tenant_id, device_name, status, settings_token, call_schedule, last_login_employee_role) \
             VALUES ($1, '端末', $2, $3, '{\"x\":1}', ARRAY['driver']) RETURNING id",
            &[&tenant, &status, &token],
        )
        .await
        .unwrap()
        .get(0)
}

/// QR 一時: 申請 → 状態 (pending・詳細なし) → 承認 → 状態 (approved・詳細と settings_token)。期限切れは expired
#[tokio::test]
async fn qr_temp_request_and_status() {
    let app = support::app().await;
    let t = tenant().await;
    let got = call(
        &app,
        "POST",
        "/api/devices/register/request",
        None,
        Some(json!({ "device_name": "受付" })),
    )
    .await;
    assert_eq!(got.status, 200);
    let body = got.json();
    let code = body["registration_code"].as_str().unwrap().to_owned();
    assert!(Uuid::parse_str(&code).is_ok() && body["expires_at"].is_string());
    let row = admin()
        .await
        .query_one(
            "SELECT flow_type, tenant_id, device_name, expires_at > NOW() + INTERVAL '9 minutes' FROM alc_api.device_registration_requests WHERE registration_code = $1",
            &[&code],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, String>(0), "qr_temp");
    assert_eq!(row.get::<_, Option<Uuid>>(1), None);
    assert_eq!(row.get::<_, String>(2), "受付");
    assert!(row.get::<_, bool>(3));
    // 名前なしの申請も通る
    let blank = call(
        &app,
        "POST",
        "/api/devices/register/request",
        None,
        Some(json!({})),
    )
    .await;
    assert_eq!(blank.status, 200);

    let status = |c: String| {
        let app = &app;
        async move {
            call(
                app,
                "GET",
                &format!("/api/devices/register/status/{c}"),
                None,
                None,
            )
            .await
        }
    };
    assert_eq!(
        status(code.clone()).await.json(),
        json!({ "status": "pending" })
    );

    let got = call(
        &app,
        "POST",
        &format!("/api/devices/approve-by-code/{code}"),
        Some(t),
        None,
    )
    .await;
    let device_id = got.json()["device_id"].clone();
    let approved = status(code.clone()).await.json();
    assert_eq!(approved["status"], "approved");
    assert_eq!(approved["device_id"], device_id);
    assert_eq!(approved["tenant_id"], json!(t));
    assert_eq!(approved["device_name"], "受付");
    let token: Uuid = serde_json::from_value(approved["settings_token"].clone()).unwrap();
    let stored: Option<Uuid> = admin()
        .await
        .query_one(
            "SELECT settings_token FROM alc_api.devices WHERE id = $1",
            &[&serde_json::from_value::<Uuid>(device_id).unwrap()],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(stored, Some(token));

    // 期限切れの pending は expired。無いコードは 404
    let expired = format!("exp-{t}");
    registration(
        &expired,
        "qr_temp",
        None,
        "pending",
        "NOW() - INTERVAL '1 minute'",
        false,
    )
    .await;
    assert_eq!(status(expired).await.json(), json!({ "status": "expired" }));
    assert_eq!(status("nothing".into()).await.status, 404);
    assert!(app.logs().is_empty());
}

/// 受け取り: URL・Device Owner は即登録 (settings_token を返す)、QR 永久は承認待ち。失敗は 400 と文言
#[tokio::test]
async fn claim_flows() {
    let app = support::app().await;
    let t = tenant().await;
    let claim = |body: Value| {
        let app = &app;
        async move { call(app, "POST", "/api/devices/register/claim", None, Some(body)).await }
    };

    // URL: 端末の入力の名前を優先
    let url = format!("url-{t}");
    let req = registration(
        &url,
        "url",
        Some(t),
        "pending",
        "NOW() + INTERVAL '1 day'",
        false,
    )
    .await;
    let got = claim(json!({ "registration_code": url, "phone_number": "09011112222", "device_name": "端末の名前" })).await;
    assert_eq!(got.status, 200);
    let body = got.json();
    assert_eq!(
        (
            body["success"].clone(),
            body["flow_type"].clone(),
            body["tenant_id"].clone()
        ),
        (json!(true), json!("url"), json!(t))
    );
    assert!(body.get("message").is_none());
    let device_id: Uuid = serde_json::from_value(body["device_id"].clone()).unwrap();
    let token: Uuid = serde_json::from_value(body["settings_token"].clone()).unwrap();
    let d = admin()
        .await
        .query_one(
            "SELECT device_name, device_type, phone_number, is_device_owner, is_dev_device, settings_token FROM alc_api.devices WHERE id = $1",
            &[&device_id],
        )
        .await
        .unwrap();
    assert_eq!(
        (
            d.get::<_, String>(0),
            d.get::<_, String>(1),
            d.get::<_, Option<String>>(2),
            d.get::<_, bool>(3),
            d.get::<_, bool>(4),
            d.get::<_, Option<Uuid>>(5)
        ),
        (
            "端末の名前".into(),
            "android".into(),
            Some("09011112222".into()),
            false,
            true,
            Some(token)
        )
    );
    let r = admin()
        .await
        .query_one("SELECT status, device_id, phone_number, device_name FROM alc_api.device_registration_requests WHERE id = $1", &[&req])
        .await
        .unwrap();
    assert_eq!(
        (
            r.get::<_, String>(0),
            r.get::<_, Option<Uuid>>(1),
            r.get::<_, Option<String>>(2),
            r.get::<_, String>(3)
        ),
        (
            "approved".into(),
            Some(device_id),
            Some("09011112222".into()),
            "端末の名前".into()
        )
    );
    // 使用済み
    let again = claim(json!({ "registration_code": url })).await;
    assert_eq!(
        (again.status, again.json()["message"].clone()),
        (400, json!("このコードは既に使用済みです"))
    );

    // Device Owner: 空の名前は管理者の名前、常に Device Owner
    let do_code = format!("do-{t}");
    registration(&do_code, "device_owner", Some(t), "pending", "NULL", false).await;
    let got = claim(json!({ "registration_code": do_code, "device_name": "" })).await;
    let id: Uuid = serde_json::from_value(got.json()["device_id"].clone()).unwrap();
    let d = admin()
        .await
        .query_one(
            "SELECT device_name, is_device_owner FROM alc_api.devices WHERE id = $1",
            &[&id],
        )
        .await
        .unwrap();
    assert_eq!(
        (d.get::<_, String>(0), d.get::<_, bool>(1)),
        ("管理者の名前".into(), true)
    );

    // QR 永久: 承認待ちのまま、電話番号と名前を入れる
    let perm = format!("perm-{t}");
    let perm_req = registration(&perm, "qr_permanent", Some(t), "pending", "NULL", false).await;
    let got = claim(json!({ "registration_code": perm, "phone_number": "0800" })).await;
    assert_eq!(
        got.json(),
        json!({ "success": true, "flow_type": "qr_permanent", "message": "管理者の承認待ちです" })
    );
    let r = admin()
        .await
        .query_one("SELECT status, phone_number, device_name FROM alc_api.device_registration_requests WHERE id = $1", &[&perm_req])
        .await
        .unwrap();
    assert_eq!(
        (
            r.get::<_, String>(0),
            r.get::<_, Option<String>>(1),
            r.get::<_, String>(2)
        ),
        ("pending".into(), Some("0800".into()), "管理者の名前".into())
    );

    // 400: 無いコード・テナント未定 (QR 一時は受け取れない)・テナントの無い URL
    let temp = format!("temp-{t}");
    registration(
        &temp,
        "qr_temp",
        None,
        "pending",
        "NOW() + INTERVAL '10 minutes'",
        false,
    )
    .await;
    let no_tenant = format!("nt-{t}");
    registration(&no_tenant, "url", None, "pending", "NULL", false).await;
    for (code, message) in [
        ("nothing".to_owned(), "無効な登録コードです"),
        (temp, "無効なフロータイプです"),
        (no_tenant, "無効なトークンです"),
    ] {
        let got = claim(json!({ "registration_code": code })).await;
        assert_eq!(got.status, 400);
        assert_eq!(
            got.json(),
            json!({ "success": false, "flow_type": "", "message": message })
        );
    }
    assert!(app.logs().is_empty());
}

/// 設定: X-Device-Token の照合 (一致・不一致 401・未送信は記録して通す・未発行の旧端末)。無い端末は 404
#[tokio::test]
async fn settings_token_rules() {
    let app = support::app().await;
    let t = tenant().await;
    let token = Uuid::new_v4();
    let with_token = device(t, "active", Some(token)).await;
    let legacy = device(t, "disabled", None).await;
    let get = |id: Uuid, header: Option<String>| {
        let app = &app;
        async move {
            let h: Vec<(&str, &str)> = header
                .iter()
                .map(|v| ("X-Device-Token", v.as_str()))
                .collect();
            call_with(
                app,
                "GET",
                &format!("/api/devices/settings/{id}"),
                None,
                &h,
                None,
            )
            .await
        }
    };
    let ok = get(with_token, Some(token.to_string())).await;
    assert_eq!(ok.status, 200);
    assert_eq!(
        ok.json(),
        json!({
            "call_enabled": false, "call_schedule": { "x": 1 }, "status": "active",
            "last_login_employee_id": null, "last_login_employee_name": null,
            "last_login_employee_role": ["driver"], "always_on": true, "bp_enabled": false,
        })
    );
    assert_eq!(get(with_token, Some("wrong".into())).await.status, 401);
    assert_eq!(get(legacy, Some(token.to_string())).await.status, 401);
    assert!(app.logs().is_empty());
    assert_eq!(get(with_token, None).await.status, 200);
    assert_eq!(
        app.logs(),
        vec!["devices: settings token not sent".to_owned()]
    );
    assert_eq!(get(legacy, None).await.json()["status"], "disabled");
    assert_eq!(get(Uuid::new_v4(), None).await.status, 404);
    support::assert_logs_clean(&app, &[with_token.to_string(), token.to_string()]);
}

/// 端末からの更新 (FCM token・最終ログイン・版・watchdog) は端末のテナントで書く。無い端末は 404
#[tokio::test]
async fn device_reports() {
    let app = support::app().await;
    let t = tenant().await;
    let d = device(t, "active", None).await;
    let emp = employee(t, "乗務 一郎").await;
    let put = |path: &str, body: Value| {
        let app = &app;
        let path = path.to_owned();
        async move { call(app, "PUT", &path, None, Some(body)).await.status }
    };
    assert_eq!(
        put(
            "/api/devices/register-fcm-token",
            json!({ "device_id": d, "fcm_token": "tok-1" })
        )
        .await,
        204
    );
    assert_eq!(
        put(
            "/api/devices/update-last-login",
            json!({ "device_id": d, "employee_id": emp, "employee_name": "乗務 一郎", "employee_role": ["driver", "manager"] })
        )
        .await,
        204
    );
    assert_eq!(
        put("/api/devices/report-version", json!({ "device_id": d, "version_code": 42, "version_name": "1.4.2", "is_dev_device": true }))
            .await,
        204
    );
    assert_eq!(
        put(
            "/api/devices/report-watchdog",
            json!({ "device_id": d, "running": true })
        )
        .await,
        204
    );
    let r = admin()
        .await
        .query_one(
            "SELECT fcm_token, last_login_employee_id, last_login_employee_name, last_login_employee_role, \
             app_version_code, app_version_name, is_device_owner, is_dev_device, app_version_reported_at IS NOT NULL, watchdog_running \
             FROM alc_api.devices WHERE id = $1",
            &[&d],
        )
        .await
        .unwrap();
    assert_eq!(r.get::<_, Option<String>>(0).as_deref(), Some("tok-1"));
    assert_eq!(r.get::<_, Option<Uuid>>(1), Some(emp));
    assert_eq!(r.get::<_, Option<String>>(2).as_deref(), Some("乗務 一郎"));
    assert_eq!(
        r.get::<_, Option<Vec<String>>>(3),
        Some(vec!["driver".into(), "manager".into()])
    );
    assert_eq!(
        (r.get::<_, Option<i32>>(4), r.get::<_, Option<String>>(5)),
        (Some(42), Some("1.4.2".into()))
    );
    assert_eq!(
        (
            r.get::<_, bool>(6),
            r.get::<_, bool>(7),
            r.get::<_, bool>(8)
        ),
        (false, true, true)
    );
    assert_eq!(r.get::<_, Option<bool>>(9), Some(true));

    let missing = Uuid::new_v4();
    assert_eq!(
        put(
            "/api/devices/report-watchdog",
            json!({ "device_id": missing, "running": false })
        )
        .await,
        404
    );
    assert_eq!(
        put(
            "/api/devices/register-fcm-token",
            json!({ "device_id": missing, "fcm_token": "x" })
        )
        .await,
        404
    );
    assert!(app.logs().is_empty());
}

/// 内部の口: 有効な端末だけテナントを返す (停止中・無い端末は 404)
#[tokio::test]
async fn pairing_tenant() {
    let app = support::app().await;
    let t = tenant().await;
    let active = device(t, "active", None).await;
    let disabled = device(t, "disabled", None).await;
    let get = |id: Uuid| {
        let app = &app;
        async move {
            call(
                app,
                "GET",
                &format!("/api/internal/devices/{id}/pairing-tenant"),
                None,
                None,
            )
            .await
        }
    };
    let ok = get(active).await;
    assert_eq!((ok.status, ok.json()), (200, json!({ "tenant_id": t })));
    assert_eq!(get(disabled).await.status, 404);
    assert_eq!(get(Uuid::new_v4()).await.status, 404);
}

#[tokio::test]
async fn db_failures_are_500_with_fixed_logs() {
    let app = build(broken_client().await);
    let id = Uuid::new_v4();
    let cases: Vec<(&str, String, Option<Value>, &str)> = vec![
        (
            "POST",
            "/api/devices/register/request".into(),
            Some(json!({})),
            "register request",
        ),
        (
            "GET",
            "/api/devices/register/status/c".into(),
            None,
            "register status",
        ),
        (
            "GET",
            format!("/api/devices/settings/{id}"),
            None,
            "settings",
        ),
        (
            "PUT",
            "/api/devices/register-fcm-token".into(),
            Some(json!({ "device_id": id, "fcm_token": "x" })),
            "fcm token",
        ),
        (
            "PUT",
            "/api/devices/update-last-login".into(),
            Some(
                json!({ "device_id": id, "employee_id": id, "employee_name": "n", "employee_role": [] }),
            ),
            "last login",
        ),
        (
            "PUT",
            "/api/devices/report-version".into(),
            Some(json!({ "device_id": id, "version_code": 1, "version_name": "1" })),
            "report version",
        ),
        (
            "PUT",
            "/api/devices/report-watchdog".into(),
            Some(json!({ "device_id": id, "running": true })),
            "report watchdog",
        ),
        (
            "GET",
            format!("/api/internal/devices/{id}/pairing-tenant"),
            None,
            "pairing tenant",
        ),
    ];
    for (method, uri, body, stage) in cases {
        let got = call(&app, method, &uri, None, body).await;
        assert_eq!(got.status, 500, "{stage}");
        assert!(
            app.logs()
                .iter()
                .any(|l| l.starts_with(&format!("devices: {stage} failed: db ("))),
            "{stage} のログ"
        );
    }
    // 受け取りの DB の失敗は rust と同じく 400 の "internal error"
    let got = call(
        &app,
        "POST",
        "/api/devices/register/claim",
        None,
        Some(json!({ "registration_code": "c" })),
    )
    .await;
    assert_eq!(
        (got.status, got.json()["message"].clone()),
        (400, json!("internal error"))
    );
    assert!(app
        .logs()
        .iter()
        .any(|l| l.starts_with("devices: claim lookup failed: db (")));
    support::assert_logs_clean(&app, &[id.to_string()]);
}

/// 受け取りの対象は引けたが、書けない (読み取りだけのロール) → 400 の "internal error"
#[tokio::test]
async fn claim_write_failures() {
    let app = build(support::client_as(support::READ_ONLY_ROLE).await);
    let t = tenant().await;
    let url = format!("rourl-{t}");
    registration(&url, "url", Some(t), "pending", "NULL", false).await;
    let perm = format!("roperm-{t}");
    registration(&perm, "qr_permanent", Some(t), "pending", "NULL", false).await;
    for (code, stage) in [(url, "claim"), (perm, "claim permanent qr")] {
        let got = call(
            &app,
            "POST",
            "/api/devices/register/claim",
            None,
            Some(json!({ "registration_code": code })),
        )
        .await;
        assert_eq!(
            (got.status, got.json()["message"].clone()),
            (400, json!("internal error")),
            "{stage}"
        );
        assert!(
            app.logs()
                .iter()
                .any(|l| l.starts_with(&format!("devices: {stage} failed: db ("))),
            "{stage}"
        );
    }
}
