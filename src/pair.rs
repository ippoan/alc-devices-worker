//! 再ペアリングの credential の発行 (`devices::re_pair::DevicePairer`) の Workers での実装:
//! auth-worker の named entrypoint `DevicePairEntrypoint` の RPC `pairInternal` (Service Binding `AUTH_DEVICE_PAIR`、本番だけ)。
//! 共有の秘密は持たない (呼べるのは binding を持つこの worker だけ)。
//!
//! 値と future は JS の値で `Send` でないので、`worker::send` の `SendWrapper`・`SendFuture` で包む (Workers は単一 thread)。
//! 戻り値が null・形が違う・throw はどれも発行の失敗 (理由は捨てる。呼び手が固定の語でログに出して 404)。
//!
//! このファイルは wasm 専用で、CI のテストと coverage の gate の外 (確かめるのは本番の実物)。

use devices::re_pair::{DevicePairer, PairError, PairedCredential};
use futures_util::future::BoxFuture;
use uuid::Uuid;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use worker::send::{SendFuture, SendWrapper};
use worker::Fetcher;

#[wasm_bindgen]
extern "C" {
    /// auth-worker の named entrypoint `DevicePairEntrypoint` (binding `AUTH_DEVICE_PAIR`)
    #[wasm_bindgen(extends = js_sys::Object)]
    type DevicePairRpc;

    #[wasm_bindgen(method, catch, js_name = pairInternal)]
    fn pair_internal(
        this: &DevicePairRpc,
        device_id: &str,
        label: &str,
    ) -> Result<js_sys::Promise, JsValue>;
}

pub struct AuthDevicePairer(SendWrapper<DevicePairRpc>);

impl AuthDevicePairer {
    pub fn new(fetcher: Fetcher) -> Self {
        Self(SendWrapper::new(fetcher.into_rpc::<DevicePairRpc>()))
    }
}

/// `{ device_id, device_secret }` の文字列の欄を読む
fn field(value: &JsValue, key: &str) -> Option<String> {
    js_sys::Reflect::get(value, &JsValue::from_str(key))
        .ok()?
        .as_string()
        .filter(|s| !s.is_empty())
}

impl DevicePairer for AuthDevicePairer {
    fn pair<'a>(
        &'a self,
        device_id: Uuid,
        label: &'a str,
    ) -> BoxFuture<'a, Result<PairedCredential, PairError>> {
        Box::pin(SendFuture::new(async move {
            let promise = self
                .0
                .pair_internal(&device_id.to_string(), label)
                .map_err(|_| PairError)?;
            let value = JsFuture::from(promise).await.map_err(|_| PairError)?;
            if value.is_null() || value.is_undefined() {
                return Err(PairError);
            }
            match (field(&value, "device_id"), field(&value, "device_secret")) {
                (Some(device_id), Some(device_secret)) => Ok(PairedCredential {
                    device_id,
                    device_secret,
                }),
                _ => Err(PairError),
            }
        }))
    }
}
