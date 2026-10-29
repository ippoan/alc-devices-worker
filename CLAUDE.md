# alc-devices-worker

端末の登録・管理の Worker `alc-devices` (Refs ippoan/rust-alc-api#680)。rust-alc-api の `crates/alc-devices` の
devices (W6b) を移す先で、path・method・JSON の形・status は rust と同じ (alc-app の管理画面・AlcoholChecker 端末・
auth-worker がそのまま使う)。口は `/api/devices/...` と `/api/internal/devices/{device_id}/pairing-tenant` (`crates/devices/src/devices.rs`)、再ペアリングの `/api/devices/re-pair`・`/api/devices/{id}/authorize-repair` (`crates/devices/src/re_pair.rs`)、FCM を送る 7 口 (`crates/devices/src/notify.rs`。送信は `fcm.rs`)。
直下 = Worker (wasm 専用)、`crates/devices/` = 口・SQL。

W6b は 3 段: a = 外を呼ばない口 / b = 再ペアリング (`re-pair`・`authorize-repair`。発行は auth-worker の RPC
`DevicePairEntrypoint.pairInternal` を本番だけの Service Binding `AUTH_DEVICE_PAIR` で呼ぶ (`src/pair.rs`)。共有の秘密は持たない。
binding の無い env では rust で発行の client が無いときと同じく 404) / c = FCM を送る 7 口 (`fcm-notify-call`・`fcm-dismiss-test`・`test-fcm`・`test-fcm-all`・`test-fcm-all-exclude`・
`trigger-update`・`trigger-update-dev`) と着信の設定の通知。c の送信は FCM HTTP v1 (`crates/devices/src/fcm.rs`): 鍵は Secrets Store の
`CHIP_REMOTE_FCM_SA_KEY` (FCM の送信専用の service account の鍵 JSON。ippoan/chip-remote と共有するオーナーの判断。secret・IAM を増やさない。
本番だけの binding、`src/fcm.rs`) で RS256 の JWT を `alc_worker_crypto::jwt::sign_rs256` で作り、`oauth2.googleapis.com/token` で
access token に替えて送る。鍵の無い env (staging・local) の FCM の口は rust の FCM が無いときと同じ 503。
`X-Internal-Secret` を照合する 3 口 (`fcm-notify-call`・`test-fcm-all-exclude`・`trigger-update-dev`) の値は Secrets Store の
`INTERNAL_SHARED_SECRET` (本番だけの binding。auth-worker・cf-alc-signaling と同じ entry を共有し、secret は増やさない)。無い env では 503
(fail-closed)。rust の頃の `FCM_INTERNAL_SECRET` は本番に無く、着信の FCM は届いていなかった (Refs ippoan/rust-alc-api#680)。

**呼び手は auth-worker の Service Binding だけ** (この Worker は認証しない)。例外は着信の FCM の 2 口 (`fcm-notify-call`・
`test-fcm-all-exclude`) で、ippoan/alc-app の cf-alc-signaling が Service Binding `ALC_DEVICES` で直接呼ぶ (`X-Internal-Secret` を照合)。管理画面の口は auth-worker が付けた
`X-Tenant-ID` (と承認者の `X-User-ID`・`X-User-Email`・`X-User-Role`) を信頼する。端末の口・内部の口は rust と同じく
テナントのヘッダを見ず、テナントは端末の ID から SECURITY DEFINER の関数で引く。auth-worker の振り分け (`ALC_BINDING_ROUTES`) は別の PR。

## コマンド
```bash
bash scripts/check-exposure.sh && bash scripts/check-exposure-test.sh
cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings
cargo clippy --target wasm32-unknown-unknown --release -- -D warnings
bash scripts/fetch-migrations.sh   # 版は scripts/ALC_MIGRATIONS_REV
DEVICES_TEST_ADMIN_DATABASE_URL=postgresql://postgres:<pw>@127.0.0.1:<port>/postgres cargo test --workspace
worker-build --release && npx wrangler@4.144.0 deploy --dry-run
```
DB テストは使い捨ての postgres:17 へ (ほかの worker のテストと同じ DB を使い回さない。準備は 1 回きりで冪等でない)。
URL が無ければ失敗 (skip しない)。接続ロールは `alc_api_rt`。

## 規範
- 公開範囲を弱めない: 本番・staging とも Service Binding だけ (どの env も `workers_dev`/`preview_urls` = false、route 無し)。
  Hyperdrive (`DEVICES_HYPERDRIVE`) は本番だけ。`wrangler.toml` の表の順を変えない (新しい表は placement より後)。
- **ログ・エラー応答は固定の語だけ。** エラーの文 (`{e}`)・tenant_id・端末の ID・登録のコード・社員の名前を出さない。
  DB の失敗は `devices: <段> failed: db (<kind>)`。応答の本文は rust と同じ (失敗は status だけ、受け取りの失敗は 400 と文言)。
- **テナントの決まる前の文** (端末の口・内部の口) は、テナントに依らない文 (SECURITY DEFINER の関数
  `lookup_device_tenant`・`get_device_settings_by_id`・`get_device_re_pair_state` と、SELECT・INSERT が USING (true) の
  `device_registration_requests`) だけを nil のテナントの transaction で流す。`devices` を読み書きするのは、テナントが決まってから。
- 端末の表の文には tenant_id を明示する (rust は RLS 任せ)。承認・却下の対象の登録は「自分のテナントかテナント未定」だけ。
- 登録のコードと settings_token は DB が作る (`gen_random_uuid()`)。wasm で乱数を引かない。
- 着信の設定 (`call-settings`) で always_on・bp_enabled を変えたら、送り終えてから 204 を返す (`notify::notify_settings_changed`。送れなくても 204)。
- FCM の失敗の文 (`test-fcm` 等の `error`) とログに、FCM・token の交換の応答の本文を載せない (status だけ)。全テナントを横断する 3 口の読み取りは
  SECURITY DEFINER の関数 (`list_fcm_devices`・`list_all_callable_devices`・`list_dev_device_tenant_ids`、migration 158) だけ。
- 再ペアリングの判定の値は rust の既定値の定数 (`re_pair::POLICY`・`WINDOW_SECS`。本番の Cloud Run は `RE_PAIR_*` を設定していなかった)。判定の「今」は DB の `now()`。
- DB は `PgClient::tenant_tx` + `query_typed` 系だけ。名前付き prepared statement 禁止。Row を tx の外へ出さない。
- `coverage_100.toml` の登録を外さない。CI の本数 (lib 14・admin_db 6・device_db 7・re_pair_db 4・notify_db 8) はテストを足したら上げる。
- public repo: ホスト名・tenant UUID・個人情報を書かない。`v*` タグ = 本番 (Tag Release 手動)。
- kit の rev は直下 `Cargo.toml` の 1 か所 (alc-people-worker と同じ rev)。
