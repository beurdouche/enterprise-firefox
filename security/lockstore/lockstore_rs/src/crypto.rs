/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use crate::LockstoreKeystoreError;
use nss_gk_api::aead::{Aead, AeadAlgorithms, Mode};
use nss_gk_api::p11;
use serde::{Deserialize, Serialize};

pub const DEFAULT_CIPHER_SUITE: CipherSuite = CipherSuite::Aes256Gcm;

/// Supported AEAD cipher suites
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CipherSuite {
    /// AES-256-GCM (default)
    Aes256Gcm,
    /// ChaCha20-Poly1305
    ChaCha20Poly1305,
}

impl Default for CipherSuite {
    fn default() -> Self {
        CipherSuite::Aes256Gcm
    }
}

impl CipherSuite {
    /// Returns the key size in bytes for this cipher suite
    pub const fn key_size(&self) -> usize {
        match self {
            CipherSuite::Aes256Gcm => 32,
            CipherSuite::ChaCha20Poly1305 => 32,
        }
    }

    /// Returns the nonce size in bytes for this cipher suite
    pub const fn nonce_size(&self) -> usize {
        match self {
            CipherSuite::Aes256Gcm => 12,
            CipherSuite::ChaCha20Poly1305 => 12,
        }
    }

    /// Returns the tag size in bytes for this cipher suite
    pub const fn tag_size(&self) -> usize {
        match self {
            CipherSuite::Aes256Gcm => 16,
            CipherSuite::ChaCha20Poly1305 => 16,
        }
    }

    fn to_nss_algorithm(&self) -> AeadAlgorithms {
        match self {
            CipherSuite::Aes256Gcm => AeadAlgorithms::Aes256Gcm,
            CipherSuite::ChaCha20Poly1305 => AeadAlgorithms::ChaCha20Poly1305,
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            CipherSuite::Aes256Gcm => "aes256gcm",
            CipherSuite::ChaCha20Poly1305 => "chacha20poly1305",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "aes256gcm" => Some(CipherSuite::Aes256Gcm),
            "chacha20poly1305" => Some(CipherSuite::ChaCha20Poly1305),
            _ => None,
        }
    }
}

/// Generates a random key using NSS for the specified cipher suite
///
/// # Arguments
/// * `cipher_suite` - The cipher suite to generate a key for
///
/// # Returns
/// A new random key as a Vec<u8>
pub fn generate_random_key(cipher_suite: CipherSuite) -> Vec<u8> {
    let key_size = cipher_suite.key_size();
    p11::random(key_size)
}

/// Encrypts data using AEAD with NSS
///
/// # Arguments
/// * `plaintext` - The data to encrypt
/// * `key` - The encryption key (must match cipher_suite.key_size())
/// * `cipher_suite` - The cipher suite to use
///
/// # Returns
/// Ciphertext with nonce prepended (nonce || ciphertext || tag)
pub fn encrypt_with_key(
    plaintext: &[u8],
    key: &[u8],
    cipher_suite: CipherSuite,
) -> Result<Vec<u8>, LockstoreKeystoreError> {
    let key_size = cipher_suite.key_size();
    let nonce_size = cipher_suite.nonce_size();

    if key.len() != key_size {
        return Err(LockstoreKeystoreError::Encryption(format!(
            "Invalid key size: expected {}, got {}",
            key_size,
            key.len()
        )));
    }

    // Generate random nonce using NSS
    let random_bytes = p11::random(nonce_size);
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[..nonce_size].copy_from_slice(&random_bytes);

    // Create NSS AEAD cipher
    let alg = cipher_suite.to_nss_algorithm();
    let nss_key = Aead::import_key(alg, key)
        .map_err(|e| LockstoreKeystoreError::Encryption(format!("Failed to import key: {}", e)))?;

    let mut aead = Aead::new(Mode::Encrypt, alg, &nss_key, nonce_bytes)
        .map_err(|e| LockstoreKeystoreError::Encryption(format!("Failed to create AEAD: {}", e)))?;

    // Encrypt the plaintext
    let ciphertext = aead
        .seal(&[], plaintext)
        .map_err(|e| LockstoreKeystoreError::Encryption(format!("Encryption failed: {}", e)))?;

    // Prepend nonce to ciphertext
    let mut result = Vec::with_capacity(nonce_size + ciphertext.len());
    result.extend_from_slice(&nonce_bytes[..nonce_size]);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Decrypts data using AEAD with NSS
///
/// # Arguments
/// * `ciphertext` - The data to decrypt (with nonce prepended)
/// * `key` - The encryption key (must match cipher_suite.key_size())
/// * `cipher_suite` - The cipher suite to use
///
/// # Returns
/// The decrypted plaintext
pub fn decrypt_with_key(
    ciphertext: &[u8],
    key: &[u8],
    cipher_suite: CipherSuite,
) -> Result<Vec<u8>, LockstoreKeystoreError> {
    let key_size = cipher_suite.key_size();
    let nonce_size = cipher_suite.nonce_size();

    if key.len() != key_size {
        return Err(LockstoreKeystoreError::Decryption(format!(
            "Invalid key size: expected {}, got {}",
            key_size,
            key.len()
        )));
    }

    if ciphertext.len() < nonce_size {
        return Err(LockstoreKeystoreError::Decryption(
            "Ciphertext too short to contain nonce".to_string(),
        ));
    }

    // Extract nonce and ciphertext
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[..nonce_size].copy_from_slice(&ciphertext[..nonce_size]);
    let actual_ciphertext = &ciphertext[nonce_size..];

    // Create NSS AEAD cipher
    let alg = cipher_suite.to_nss_algorithm();
    let nss_key = Aead::import_key(alg, key)
        .map_err(|e| LockstoreKeystoreError::Decryption(format!("Failed to import key: {}", e)))?;

    let mut aead = Aead::new(Mode::Decrypt, alg, &nss_key, nonce_bytes)
        .map_err(|e| LockstoreKeystoreError::Decryption(format!("Failed to create AEAD: {}", e)))?;

    // Decrypt the ciphertext
    let plaintext = aead
        .open(&[], 0, actual_ciphertext)
        .map_err(|e| LockstoreKeystoreError::Decryption(format!("Decryption failed: {}", e)))?;

    Ok(plaintext)
}
