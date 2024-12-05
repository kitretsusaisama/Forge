use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{Context, Result};
use secrecy::{Secret, ExposeSecret};
use generic_array::GenericArray;
use rand_core::OsRng;

const NONCE_SIZE: usize = 12;

pub struct Encryption {
    key: Secret<String>,
}

impl Encryption {
    pub fn new(key: &Secret<String>) -> Result<Self> {
        Ok(Self { key: key.clone() })
    }

    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let key = GenericArray::from_slice(self.key.expose_secret());
        let cipher = Aes256Gcm::new(key);
        
        let ciphertext = cipher
            .encrypt(nonce, data)
            .map_err(|_| anyhow::anyhow!("Encryption failed"))?;

        let mut output = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&ciphertext);
        Ok(output)
    }

    pub fn decrypt(&self, encrypted_data: &[u8]) -> Result<Vec<u8>> {
        if encrypted_data.len() < NONCE_SIZE {
            return Err(anyhow::anyhow!("Invalid encrypted data"));
        }

        let (nonce_bytes, ciphertext) = encrypted_data.split_at(NONCE_SIZE);
        let nonce = Nonce::from_slice(nonce_bytes);
        
        let key = GenericArray::from_slice(self.key.expose_secret());
        let cipher = Aes256Gcm::new(key);

        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| anyhow::anyhow!("Decryption failed"))
    }
}
