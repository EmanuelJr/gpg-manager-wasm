use crate::key::KeyType;
use hex;
use js_sys::Array;
use pgp::crypto::{HashAlgorithm, SymmetricKeyAlgorithm};
use pgp::types::{KeyTrait, SecretKeyTrait};
use pgp::{Deserializable, Message, PublicOrSecret};
use std::collections::HashMap;
use std::io::{Cursor, Read};
use wasm_bindgen::prelude::*;

// Same algorithms used in OpenPGP by default
const DEFAULT_SYMMETRIC_ALGORITHM: SymmetricKeyAlgorithm = SymmetricKeyAlgorithm::AES256;
const DEFAULT_HASH_ALGORITHM: HashAlgorithm = HashAlgorithm::SHA2_512;

#[wasm_bindgen]
pub struct KeyRing {
    public_key: HashMap<String, pgp::SignedPublicKey>,
    secret_key: HashMap<String, pgp::SignedSecretKey>,
    password: HashMap<String, String>,
}

#[wasm_bindgen]
impl KeyRing {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        let public_key = HashMap::new();
        let secret_key = HashMap::new();
        let password = HashMap::new();

        KeyRing {
            public_key,
            secret_key,
            password,
        }
    }

    fn get_key_id_from_fingerprint(fingerprint: &str) -> &str {
        let len = fingerprint.len();
        &fingerprint[len - 16..]
    }

    fn get_key(&self, key_type: KeyType, fingerprint: &str) -> Result<PublicOrSecret, &str> {
        let key_id = KeyRing::get_key_id_from_fingerprint(fingerprint);

        let key = match key_type {
            KeyType::Public => {
                let public_key = self.public_key.get(key_id).ok_or("Public key not found")?;
                PublicOrSecret::Public(public_key.clone())
            }
            KeyType::Secret => {
                let secret_key = self.secret_key.get(key_id).ok_or("Secret key not found")?;
                PublicOrSecret::Secret(secret_key.clone())
            }
        };

        Ok(key)
    }

    fn get_key_password(&self, fingerprint: &str) -> Result<String, &str> {
        let key_id = KeyRing::get_key_id_from_fingerprint(fingerprint);
        self.password
            .get(key_id)
            .ok_or("Password not found")
            .map(|s| s.to_string())
    }

    #[wasm_bindgen(js_name = "loadKeys")]
    pub fn load_keys(&mut self, keys: &str) -> Array {
        let (keys, _) = pgp::from_armor_many(Cursor::new(keys)).unwrap();

        let keys: Vec<(String, PublicOrSecret)> = keys
            .filter_map(|key| match key {
                Ok(key) => key
                    .verify()
                    .ok()
                    .map(|_| (hex::encode(key.key_id().to_vec()), key)),
                Err(_) => None,
            })
            .collect();

        keys.iter().for_each(|(key_id, key)| {
            if key.is_public() {
                self.public_key
                    .insert(key_id.clone(), key.clone().into_public());
            } else {
                self.secret_key
                    .insert(key_id.clone(), key.clone().into_secret());
            }
        });

        keys.iter()
            .map(|(key_id, _)| key_id)
            .map(JsValue::from)
            .collect()
    }

    #[wasm_bindgen(js_name = "unlockKey")]
    pub fn unlock_key(&mut self, fingerprint: &str, key_password: &str) -> Result<(), JsValue> {
        let secret_key = self.get_key(KeyType::Secret, fingerprint)?.into_secret();
        secret_key
            .unlock(|| key_password.to_string(), |_| Ok(()))
            .map_err(|_| "Invalid password")?;

        self.password.insert(
            hex::encode(secret_key.key_id().to_vec()),
            key_password.to_string(),
        );

        Ok(())
    }

    #[wasm_bindgen(js_name = "verifySignature")]
    pub fn verify_signature(
        &self,
        fingerprint: &str,
        signature: &str,
        data: &str,
    ) -> Result<(), JsValue> {
        let (msg, _) = Message::from_armor_single(Cursor::new(signature))
            .map_err(|_| "Failed to parse message")?;

        let public_key = self.get_key(KeyType::Public, fingerprint)?.into_public();

        match &msg {
            Message::Signed {
                message: _,
                one_pass_signature: _,
                signature,
            } => signature
                .verify(&public_key, Cursor::new(data))
                .map_err(|_| "Failed to verify signature".into()),
            _ => Err("Invalid message type".into()),
        }
    }

    #[wasm_bindgen]
    pub fn encrypt(&self, fingerprint: &str, data: &str) -> Result<String, JsValue> {
        let public_key = self.get_key(KeyType::Public, fingerprint)?.into_public();

        let mut rng = rand::thread_rng();

        let message = Message::new_literal_bytes("", data.as_bytes());
        let encrypted_message = message
            .encrypt_to_keys(&mut rng, DEFAULT_SYMMETRIC_ALGORITHM, &[&public_key])
            .map_err(|_| "Failed to encrypt message")?;

        Ok(encrypted_message
            .to_armored_string(None)
            .map_err(|_| "Failed to encode message")?)
    }

    #[wasm_bindgen]
    pub fn decrypt(&self, fingerprint: &str, message: &str) -> Result<String, JsValue> {
        let secret_key = self.get_key(KeyType::Secret, fingerprint)?.into_secret();
        let key_password = self.get_key_password(fingerprint)?;

        let (encrypted_message, _) = Message::from_armor_single(Cursor::new(message))
            .map_err(|_| "Failed to parse message")?;

        let message = match &encrypted_message {
            Message::Encrypted { .. } => {
                let (mut decrypter, _ids) = encrypted_message
                    .decrypt(|| String::new(), || key_password, &[&secret_key])
                    .map_err(|_| "Failed to init decryption")?;

                let decrypted = decrypter
                    .next()
                    .ok_or("No message to decrypt message")?
                    .map_err(|_| "Message decryption failed")?;

                let raw_data = match &decrypted {
                    Message::Literal(data) => data.data().to_vec(),
                    Message::Compressed(data) => {
                        let mut buffer = Vec::new();
                        data.decompress()
                            .map_err(|_| "Failed to decompress message")?
                            .read_to_end(&mut buffer)
                            .map_err(|_| "Failed to read decompressed message")?;

                        buffer.clone()
                    }
                    _ => panic!("Unexpected message type: {:?}", decrypted),
                };
                raw_data
            }
            _ => panic!("Unexpected message type: {:?}", encrypted_message),
        };

        Ok(std::str::from_utf8(message.as_slice()).unwrap().into())
    }

    #[wasm_bindgen]
    pub fn sign(&self, fingerprint: &str, data: &str) -> Result<JsValue, JsValue> {
        let secret_key = self.get_key(KeyType::Secret, fingerprint)?.into_secret();
        let key_password = self.get_key_password(fingerprint)?;

        let message = Message::new_literal_bytes("", data.as_bytes());
        let signature = message
            .sign(&secret_key, || key_password, DEFAULT_HASH_ALGORITHM)
            .map_err(|_| "Failed to sign message")?
            .to_armored_string(None)
            .map_err(|_| "Failed to encode message")?;

        Ok(signature.into())
    }
}
