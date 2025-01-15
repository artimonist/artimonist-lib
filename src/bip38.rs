use bitcoin::{
    base58,
    hashes::{sha256, Hash},
    key::{FromWifError, Secp256k1},
    secp256k1::{self, SecretKey},
    Address, NetworkKind, PrivateKey,
};
use thiserror::Error;
use unicode_normalization::{self, UnicodeNormalization};

/// BIP38 Implementation
///
/// Passphrase-protected private key
///
/// see: [BIP38 spec](https://bips.dev/38/)
///
/// ### Examples
/// ```
/// # use artimonist::Encryptor;
/// assert_eq!(Encryptor::encrypt_wif("L3zftSdXx3wcHktnZ295fTmhd6mCgFRykQruWXdRj39BgbLPTzUz", "🍔🍟🌭🍦"),
///     Ok("6PYK94C6t87WJp87F6njuTinyHJAWRvApjXybsy6CyBxor1PRacypM4EXy".to_owned()));
///
/// assert_eq!(Encryptor::decrypt_wif("6PYK94C6t87WJp87F6njuTinyHJAWRvApjXybsy6CyBxor1PRacypM4EXy", "🍔🍟🌭🍦"),
///     Ok("L3zftSdXx3wcHktnZ295fTmhd6mCgFRykQruWXdRj39BgbLPTzUz".to_owned()));
/// ```
///

// # Reference
// [1] - [BIP38 spec](https://bips.dev/38/)
// [2] - [Ref crate](https://crates.io/crates/bip38)
//
pub struct Encryptor {}

/// Number of base58 characters on every encrypted private key.
const LEN_EKEY: usize = 58;

/// Prefix of all private keys encrypted with bip-0038 standard.
const PRE_EKEY: &str = "6P";

/// Prefix of all non ec encrypted keys.
const PRE_NON_EC: [u8; 2] = [0x01, 0x42];

/// Prefix of all ec encrypted keys.
const PRE_EC: [u8; 2] = [0x01, 0x43];

impl Encryptor {
    fn aes_encrypt(key: &[u8], data: &[u8]) -> Vec<u8> {
        use crypto::buffer::{RefReadBuffer, RefWriteBuffer};
        use crypto::{aes::KeySize::KeySize256, blockmodes::NoPadding};

        let mut cipher = crypto::aes::ecb_encryptor(KeySize256, key, NoPadding);
        let mut out = Vec::with_capacity(data.len());
        out.resize(data.len(), 0);
        let _ = cipher.encrypt(
            &mut RefReadBuffer::new(&data[..]),
            &mut RefWriteBuffer::new(&mut out),
            true,
        ); // ignore error of: InvalidLength, InvalidPadding.
        out
    }

    fn aes_decrypt(key: &[u8], data: &[u8]) -> Vec<u8> {
        use crypto::buffer::{RefReadBuffer, RefWriteBuffer};
        use crypto::{aes::KeySize::KeySize256, blockmodes::NoPadding};
        let mut cipher = crypto::aes::ecb_decryptor(KeySize256, key, NoPadding);
        let mut out = Vec::with_capacity(data.len());
        out.resize(data.len(), 0);
        let _ = cipher.decrypt(
            &mut RefReadBuffer::new(&data[..]),
            &mut RefWriteBuffer::new(&mut out),
            true,
        );
        out
    }

    /// encrypt private key
    pub fn encrypt_wif(wif: &str, pwd: &str) -> EncryptResult<String> {
        let private_key = PrivateKey::from_wif(wif)?;
        let salt = {
            // checksum
            let pub_key = private_key.public_key(&Secp256k1::default());
            let address = Address::p2pkh(&pub_key, NetworkKind::Main).to_string();
            sha256::Hash::hash(address.as_bytes()).hash_again()[..4].to_vec()
        };
        let mut scryptor = [0; 64];
        {
            let param = crypto::scrypt::ScryptParams::new(14, 8, 8);
            let nfc = pwd.nfc().collect::<String>();
            crypto::scrypt::scrypt(nfc.as_bytes(), &salt, &param, &mut scryptor);
        }
        let data = {
            let half: Vec<u8> = (0..32)
                .map(|i| scryptor[i] ^ private_key.inner.secret_bytes()[i])
                .collect();
            let o1 = Self::aes_encrypt(&scryptor[32..], &half[..16]);
            let o2 = Self::aes_encrypt(&scryptor[32..], &half[16..]);
            [o1, o2].concat()
        };
        let buffer = [
            &PRE_NON_EC[..2],
            &[if private_key.compressed { 0xe0 } else { 0xc0 }],
            &salt[..4],
            &data[..32],
        ]
        .concat();
        Ok(base58::encode_check(&buffer))
    }

    /// decrypt private key
    pub fn decrypt_wif(secret: &str, pwd: &str) -> EncryptResult<String> {
        if secret.len() != LEN_EKEY || !secret.as_bytes().starts_with(PRE_EKEY.as_bytes()) {
            return Err(EncryptError::InvalidSecret);
        }
        match base58::decode_check(secret)? {
            mut vs if vs[..2] == PRE_NON_EC => Self::decrypt_non_ec(&mut vs, pwd),
            vs if vs[..2] == PRE_EC => Err(EncryptError::UnSupportedType),
            _ => Err(EncryptError::InvalidSecret),
        }
    }

    fn decrypt_non_ec(secret: &[u8], pwd: &str) -> EncryptResult<String> {
        assert!(secret.len() == 39 && secret[..2] == PRE_NON_EC);

        let mut scrypt_key = [0; 64];
        {
            let param = crypto::scrypt::ScryptParams::new(14, 8, 8);
            let nfc = pwd.nfc().collect::<String>();
            crypto::scrypt::scrypt(nfc.as_bytes(), &secret[3..7], &param, &mut scrypt_key);
        }
        let private_key = {
            let data = {
                let mut o1 = Self::aes_decrypt(&scrypt_key[32..], &secret[7..23]);
                let mut o2 = Self::aes_decrypt(&scrypt_key[32..], &secret[23..39]);
                (0..16).for_each(|i| {
                    o1[i] ^= scrypt_key[i];
                    o2[i] ^= scrypt_key[i + 16];
                });
                [o1, o2].concat()
            };
            PrivateKey {
                compressed: (secret[2] & 0x20) == 0x20,
                network: NetworkKind::Main,
                inner: SecretKey::from_slice(&data)?,
            }
        };
        {
            let checksum = {
                let pub_key = private_key.public_key(&Secp256k1::default());
                let address = Address::p2pkh(&pub_key, NetworkKind::Main).to_string();
                &sha256::Hash::hash(address.as_bytes()).hash_again()[..4]
            };
            if checksum != &secret[3..7] {
                return Err(EncryptError::InvalidSecret);
            }
        }
        Ok(private_key.to_wif())
    }
}

/// Encrypt error
#[derive(Error, Debug, PartialEq)]
pub enum EncryptError {
    /// Invalid encrypted wif
    #[error("invalid secret key")]
    InvalidSecret,
    /// EC mode not supported
    #[error("unsupported secret key")]
    UnSupportedType,
    /// Invalid wif
    #[error("invalid wif")]
    InvalidWif(#[from] FromWifError),
    /// Invalid base58 str
    #[error("decode error")]
    Base58Error(#[from] base58::Error),
    /// Secp error
    #[error("secp error")]
    SecpError(#[from] secp256k1::Error),
}

pub(crate) type EncryptResult<T = ()> = Result<T, EncryptError>;

#[cfg(test)]
mod bip38_test {
    use super::*;

    /// <https://www.bitaddress.org>
    #[test]
    fn test_bip38() -> EncryptResult {
        const TEST_DATA: &[[&str; 3]] = &[
            [
                "TestingOneTwoThree",
                "6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg",
                "5KN7MzqK5wt2TP1fQCYyHBtDrXdJuXbUzm4A9rKAteGu3Qi5CVR",
                // Unencrypted (hex): CBF4B9F70470856BB4F40F80B87EDB90865997FFEE6DF315AB166D713AF433A5
            ],
            [
                "Satoshi",
                "6PRNFFkZc2NZ6dJqFfhRoFNMR9Lnyj7dYGrzdgXXVMXcxoKTePPX1dWByq",
                "5HtasZ6ofTHP6HCwTqTkLDuLQisYPah7aUnSKfC7h4hMUVw2gi5",
                // Unencrypted (hex): 09C2686880095B1A4C249EE3AC4EEA8A014F11E6F986D0B5025AC1F39AFBD9AE
            ],
            [
                "TestingOneTwoThree",
                "6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s6DGhwP4J5o44cvXdoY7sRzhtpUeo",
                "L44B5gGEpqEDRS9vVPz7QT35jcBG2r3CZwSwQ4fCewXAhAhqGVpP",
            ],
            [
                "Satoshi",
                "6PYLtMnXvfG3oJde97zRyLYFZCYizPU5T3LwgdYJz1fRhh16bU7u6PPmY7",
                "KwYgW8gcxj1JWJXhPSu4Fqwzfhp5Yfi42mdYmMa4XqK7NJxXUSK7",
            ],
            [
                "\u{03d2}\u{0301}\u{0000}\u{010400}\u{01f4a9}", // "ϓ␀𐐀💩",
                "6PRW5o9FLp4gJDDVqJQKJFTpMvdsSGJxMYHtHaQBF3ooa8mwD69bapcDQn",
                "5Jajm8eQ22H3pGWLEVCXyvND8dQZhiQhoLJNKjYXk9roUFTMSZ4",
                // Bitcoin Address: 16ktGzmfrurhbhi6JGqsMWf7TyqK9HNAeF
            ],
            [
                "🍔🍟🌭🍦",
                "6PYQEYUvYDGpvMnyoEoTFPovQ6ZxroRVUFUSqVGQ3zCf3vRP5nFGS934rm",
                "L4qD92jn8TTsZ8waNUtraR17ipZkzkvop3GkcNiFP3LJNVk9tXQT",
            ],
        ];
        for data in TEST_DATA {
            let wif = Encryptor::decrypt_wif(data[1], data[0])?;
            assert_eq!(wif, data[2]);
            let secret = Encryptor::encrypt_wif(data[2], data[0])?;
            assert_eq!(secret, data[1]);
        }
        Ok(())
    }
}
