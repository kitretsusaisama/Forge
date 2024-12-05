use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{Context, Result};
use secrecy::{Secret, ExposeSecret};

pub struct Encryption {
    cipher: Aes256Gcm,
}

impl Encryption {
    pub fn new(key: &Secret<String>) -> Result<Self> {
        let key_bytes = key.expose_secret().as_bytes();
        let key = Key::<Aes256Gcm>::from_slice(key_bytes);
        let cipher = Aes256Gcm::new(key);
        Ok(Self { cipher })
    }

    pub fn encrypt(&self, data: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
        let nonce = Nonce::from_slice(nonce);
        self.cipher
            .encrypt(nonce, data)
            .context("Failed to encrypt data")
    }

    pub fn decrypt(&self, ciphertext: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
        let nonce = Nonce::from_slice(nonce);
        self.cipher
            .decrypt(nonce, ciphertext)
            .context("Failed to decrypt data")
    }
}
