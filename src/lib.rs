//! This crate implements a wrapper around a secret that is stored in memory.
//!
//! `Protected` allows a program to store a encrypted secret in memory. The secret
//! is encrypted using XChaChaPoly1305. The encryption keys are large enough to mitigate
//! memory side channel attacks like Spectre, Meltdown, Rowhammer, and RamBleed.
//!
//! There is a pre_key and a nonce each large enough to limit these attacks.
//! The pre_key and nonce are feed into a merlin transcript to mix with other data
//! and derive the actual encryption key. This value is wiped from memory when the dropped
//! or decrypted.
#![deny(
    warnings,
    missing_docs,
    unsafe_code,
    dead_code,
)]

use chacha20poly1305::{
    KeyInit,
    aead::AeadInPlace,
    Key, XChaCha20Poly1305, XNonce,
};
use rand::RngCore;
use zeroize::Zeroize;


const BUF_SIZE: usize = 16 * 1024;

/// A protected region of memory.
/// The pre key is large to inhibit speculation and sidechannel attacks
/// like Spectre, Meltdown, Rowhammer, and RamBleed. Uses
/// XChacha20Poly1305 to encrypt/decrypt the data in memory in place.
///
/// The prekey random nonce are hashed using merlin transcripts to construct the
/// sealing key and encryption nonce.
/// Standard traits are intentionally not implemented to avoid memory copies like
/// [`Copy`], [`Clone`], [`Debug`], [`ToString`].
pub struct Protected {
    /// The key for protecting the value
    pre_key: [u8; BUF_SIZE],
    /// The current nonce
    nonce: [u8; BUF_SIZE],
    /// The encrypted value
    value: Vec<u8>,
}

impl Protected {
    /// Create a new protected memory value
    pub fn new(secret: &[u8]) -> Self {
        let mut protected = Self {
            pre_key: [0u8; BUF_SIZE],
            nonce: [0u8; BUF_SIZE],
            value: secret.to_vec(),
        };
        protected.protect();
        protected
    }

    fn protect(&mut self) {
        let mut rng = rand::rngs::OsRng {};
        rng.fill_bytes(&mut self.pre_key);
        rng.fill_bytes(&mut self.nonce);
        let mut transcript = merlin::Transcript::new(b"protect memory region");
        transcript.append_message(b"pre_key", &self.pre_key);
        transcript.append_message(b"nonce", &self.nonce);
        let mut output = [0u8; 64];
        transcript.challenge_bytes(b"seal_data", &mut output);
        let seal_key = Key::from_slice(&output[..32]);
        let nonce = XNonce::from_slice(&output[32..56]);
        let cipher = XChaCha20Poly1305::new(seal_key);
        let mut aad = Vec::with_capacity(2 * BUF_SIZE);
        aad.extend_from_slice(&self.pre_key);
        aad.extend_from_slice(&self.nonce);
        cipher
            .encrypt_in_place(&nonce, &aad, &mut self.value)
            .unwrap();
        output.zeroize();
    }

    /// Unprotect memory value
    pub fn unprotect(&mut self) -> Option<Unprotected<'_>> {
        let mut transcript = merlin::Transcript::new(b"protect memory region");
        transcript.append_message(b"pre_key", &self.pre_key);
        transcript.append_message(b"nonce", &self.nonce);
        let mut output = [0u8; 64];
        transcript.challenge_bytes(b"seal_data", &mut output);
        let seal_key = Key::from_slice(&output[..32]);
        let nonce = XNonce::from_slice(&output[32..56]);
        let cipher = XChaCha20Poly1305::new(seal_key);
        let mut aad = Vec::with_capacity(2 * BUF_SIZE);
        aad.extend_from_slice(&self.pre_key);
        aad.extend_from_slice(&self.nonce);
        match cipher.decrypt_in_place(&nonce, &aad, &mut self.value) {
            Err(_) => None,
            Ok(_) => {
                self.pre_key.zeroize();
                self.nonce.zeroize();
                aad.zeroize();
                Some(Unprotected { protected: self })
            }
        }
    }
}

impl Drop for Protected {
    fn drop(&mut self) {
        self.pre_key.zeroize();
        self.nonce.zeroize();
    }
}

/// Unprotected contains the decrypted value.
/// After Unprotected is dropped, the `Protected` is reengaged
/// with new cryptographic material and the value is encrypted again
pub struct Unprotected<'a> {
    protected: &'a mut Protected,
}

impl<'a> AsRef<[u8]> for Unprotected<'a> {
    fn as_ref(&self) -> &[u8] {
        self.protected.value.as_slice()
    }
}

impl<'a> AsMut<[u8]> for Unprotected<'a> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.protected.value.as_mut()
    }
}

impl<'a> Drop for Unprotected<'a> {
    fn drop(&mut self) {
        self.protected.protect();
    }
}

#[test]
fn protect_test() {
    let password = b"letmeinplease!";
    let mut p = Protected::new(&password[..]);
    assert_ne!(p.value, password);
    assert_eq!(p.value.len(), password.len() + 16);
    assert_ne!(p.pre_key, [0u8; BUF_SIZE]);
    assert_ne!(p.nonce, [0u8; BUF_SIZE]);

    let password2 = p.unprotect();
    assert!(password2.is_some());
    assert_eq!(password2.unwrap().as_ref(), password.as_slice());
}