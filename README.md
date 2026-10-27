# alc-devices-worker

alc の端末の登録・管理の Cloudflare Worker `alc-devices`。rust-alc-api (Cloud Run) の `crates/alc-devices` を移したもの
(W6b、Refs ippoan/rust-alc-api#680)。型は ippoan/alc-people-worker と同じ。呼び手は auth-worker の Service Binding だけ。

## 口 (path・method・JSON の形・status は rust-alc-api と同じ)

管理画面 (`X-Tenant-ID` 必須):

| path | method | 中身 |
|---|---|---|
| `/api/devices` | GET | 端末の一覧 (作成の新しい順) |
| `/api/devices/pending` | GET | 承認待ちの登録 (自分のテナントとテナント未定、期限内) |
| `/api/devices/register/create-token` | POST | URL の登録のコード (24 時間) と URL |
| `/api/devices/register/create-permanent-qr` | POST | QR 永久の登録のコード |
| `/api/devices/register/create-device-owner-token` | POST | Device Owner の登録のコード |
| `/api/devices/approve/{id}`・`/api/devices/approve-by-code/{code}` | POST | 承認 (端末を作り、登録を approved に) |
| `/api/devices/reject/{id}`・`/disable/{id}`・`/enable/{id}` | POST | 却下・停止・再開 (204。無ければ 404) |
| `/api/devices/{id}` | DELETE | 削除 (204。無ければ 404) |
| `/api/devices/{id}/call-settings` | PUT | 着信の設定 (204) |

端末 (テナントは端末の ID から引く):

| path | method | 中身 |
|---|---|---|
| `/api/devices/register/request` | POST | QR 一時の登録の申請 (10 分) |
| `/api/devices/register/status/{code}` | GET | 登録の状態 (approved までは端末・テナントを返さない) |
| `/api/devices/register/claim` | POST | 受け取り (URL・Device Owner は即登録、QR 永久は承認待ち) |
| `/api/devices/settings/{device_id}` | GET | 端末の設定 (`X-Device-Token` を照合) |
| `/api/devices/register-fcm-token`・`update-last-login`・`report-version`・`report-watchdog` | PUT | 端末からの更新 (204) |

内部: `GET /api/internal/devices/{device_id}/pairing-tenant` — 有効な端末のテナント (auth-worker の device credential 発行)。

再ペアリング (`re-pair`・`authorize-repair`) と FCM を送る口はまだ rust-alc-api に在る (W6b-b・W6b-c)。

## 開発

`CLAUDE.md` のコマンドを参照。デプロイは `.github/workflows/deploy.yml` (main = staging、タグ `v*` = 本番)。
