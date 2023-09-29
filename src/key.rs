use pgp::key::{KeyType as KT, SecretKeyParamsBuilder};
use pgp::types::SecretKeyTrait;
use std::time::Duration;
use wasm_bindgen::prelude::*;

pub enum KeyType {
    Public,
    Secret,
}

#[wasm_bindgen]
pub struct KeyPair {
    public_key: String,
    private_key: String,
}

#[wasm_bindgen]
impl KeyPair {
    #[wasm_bindgen(getter, js_name = "publicKey")]
    pub fn public_key(&self) -> String {
        self.public_key.clone()
    }

    #[wasm_bindgen(getter, js_name = "privateKey")]
    pub fn private_key(&self) -> String {
        self.private_key.clone()
    }
}

#[wasm_bindgen(js_name = "generateKey")]
pub fn generate_key(
    key_bits: u32,
    expiration_seconds: Option<u64>,
    full_name: &str,
    email: &str,
    password: &str,
) -> Result<KeyPair, JsValue> {
    let key_params = SecretKeyParamsBuilder::default()
        .key_type(KT::Rsa(key_bits))
        .expiration(expiration_seconds.map(Duration::from_secs))
        .can_create_certificates(true)
        .can_sign(true)
        .can_encrypt(true)
        .primary_user_id(format!("{} <{}>", full_name, email))
        .passphrase(Some(password.to_string()))
        .build()
        .unwrap();

    let mut rng = rand::thread_rng();
    let secret_key = key_params
        .generate_with_rng(&mut rng)
        .map_err(|_| "Failed to generate secret key")?
        .sign(|| password.to_string())
        .unwrap();

    let public_key = secret_key
        .public_key()
        .sign(&secret_key, || password.to_string())
        .unwrap();

    let key_pair = KeyPair {
        private_key: secret_key.to_armored_string(None).unwrap(),
        public_key: public_key.to_armored_string(None).unwrap(),
    };

    Ok(key_pair)
}
