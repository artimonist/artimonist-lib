/*!
 * Tests BIP 85 algorithm
 */
#![allow(unused)]
///
/// # Reference
/// [1] - BIP 85: Deterministic Entropy From BIP32 Keychains
///       https://bips.dev/85/
///       https://github.com/ethankosakovsky/bip85
///       https://github.com/rikitau/rust-bip85
///
/// # Examples
///   bip39: 83696968'/39'/language'/words'/index'
///   wif: m/83696968'/2'/index'
///   hex: m/83696968'/128169p'/index'
///   xpriv: 83696968'/32'/index'
///
#[cfg(test)]
mod pre_test_bip85 {
    use std::str::FromStr;

    use bitcoin::{
        base64::Engine,
        bip32::{ChildNumber, Xpriv},
        hashes::{hmac, sha512, Hash, HashEngine},
        hex::DisplayHex,
        secp256k1::SecretKey,
        NetworkKind,
    };

    const MASTER_KEY_STR: &str = "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb";

    fn master_derive(path: &str) -> Result<Vec<u8>, bitcoin::bip32::Error> {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let master = bitcoin::bip32::Xpriv::from_str(MASTER_KEY_STR)?;
        let path = bitcoin::bip32::DerivationPath::from_str(path)?;
        let derived = master.derive_priv(&secp, &path)?;

        let mut hmac =
            bitcoin::hashes::hmac::HmacEngine::<sha512::Hash>::new("bip-entropy-from-k".as_bytes());
        hmac.input(&derived.private_key.secret_bytes());
        let data = hmac::Hmac::from_engine(hmac).to_byte_array();

        Ok(data.to_vec())
    }

    /// BIP39
    /// Application number: 39'
    /// The derivation path format is: m/83696968'/39'/{language}'/{words}'/{index}'
    ///
    #[ignore = "pre test"]
    #[test]
    fn pre_test_to_mnemonic() -> Result<(), bitcoin::bip32::Error> {
        struct Case<'a> {
            pub count: usize,
            pub path: &'a str,
            pub data: &'a str,
            pub words: &'a str,
        }
        const TEST_CASE: &[Case] = &[
            Case{
                // 12 English words
                count: 12,
                path: "m/83696968'/39'/0'/12'/0'",
                data: "6250b68daf746d12a24d58b4787a714b",
                words: "girl mad pet galaxy egg matter matrix prison refuse sense ordinary nose",
            },
            Case{
                // 18 English words
                count: 18,
                path: "m/83696968'/39'/0'/18'/0'",
                data: "938033ed8b12698449d4bbca3c853c66b293ea1b1ce9d9dc",
                words: "near account window bike charge season chef number sketch tomorrow excuse sniff circle vital hockey outdoor supply token",
            },
            Case {
                // 24 English words
                count: 24,
                path: "m/83696968'/39'/0'/24'/0'",
                data: "ae131e2312cdc61331542efe0d1077bac5ea803adf24b313a4f0e48e9c51f37f",
                words: "puppy ocean match cereal symbol another shed magic wrap hammer bulb intact gadget divorce twin tonight reason outdoor destroy simple truth cigar social volcano",
            },
        ];

        for case in TEST_CASE.iter() {
            let data = master_derive(case.path)?;
            let len = case.count * 4 / 3;
            assert_eq!(data[..len].to_lower_hex_string(), case.data);
        }
        Ok(())
    }

    /// HD-Seed WIF
    /// Application number: 2'
    /// Path format is m/83696968'/2'/{index}'
    ///
    #[ignore = "pre test"]
    #[test]
    fn pre_test_to_wif() -> Result<(), bitcoin::bip32::Error> {
        const WIF_PATH: &str = "m/83696968'/2'/0'";
        const PRIV_KEY: &str = "Kzyv4uF39d4Jrw2W7UryTHwZr1zQVNk4dAFyqE6BuMrMh1Za7uhp";
        let data = master_derive(WIF_PATH)?;
        let priv_key = bitcoin::PrivateKey::from_slice(&data[..32], NetworkKind::Main)?;
        assert_eq!(priv_key.to_wif(), PRIV_KEY);
        Ok(())
    }

    /// XPRV
    /// Application number: 32'
    /// Path format is m/83696968'/32'/{index}'
    ///
    #[ignore = "pre test"]
    #[test]
    fn pre_test_to_xpriv() -> Result<(), bitcoin::bip32::Error> {
        const XPRIV_PATH: &str = "m/83696968'/32'/0'";
        const DERIVED_ENTROPY: &str =
            "ead0b33988a616cf6a497f1c169d9e92562604e38305ccd3fc96f2252c177682";
        const DERIVED_XPRIV: &str = "xprv9s21ZrQH143K2srSbCSg4m4kLvPMzcWydgmKEnMmoZUurYuBuYG46c6P71UGXMzmriLzCCBvKQWBUv3vPB3m1SATMhp3uEjXHJ42jFg7myX";

        let data = master_derive(XPRIV_PATH)?;
        let chain_code = bitcoin::bip32::ChainCode::from_hex(&data[..32].to_lower_hex_string())
            .expect("chain_code");
        let xpriv = Xpriv {
            network: NetworkKind::Main,
            depth: 0,
            parent_fingerprint: Default::default(),
            child_number: ChildNumber::Normal { index: 0 },
            private_key: SecretKey::from_slice(&data[32..]).unwrap(),
            chain_code: chain_code,
        };
        let ext_xpriv = Xpriv::from_str(DERIVED_XPRIV).unwrap();
        assert_eq!(xpriv, Xpriv::from_str(DERIVED_XPRIV).unwrap());
        Ok(())
    }

    /// HEX
    /// Application number: 128169'
    /// The derivation path format is: m/83696968'/128169'/{num_bytes}'/{index}'
    /// 16 <= num_bytes <= 64
    /// Truncate trailing (least significant) bytes of the entropy after num_bytes
    ///
    #[ignore = "pre test"]
    #[test]
    fn pre_test_to_hex() -> Result<(), bitcoin::bip32::Error> {
        const HEX_LEN: usize = 64;
        let hex_path = format!("m/83696968'/128169'/{HEX_LEN}'/0'");
        const HEX_64_STR: &str = "492db4698cf3b73a5a24998aa3e9d7fa96275d85724a91e71aa2d645442f878555d078fd1f1f67e368976f04137b1f7a0d19232136ca50c44614af72b5582a5c";
        let data = master_derive(&hex_path)?;
        assert_eq!(data[..64].to_lower_hex_string(), HEX_64_STR);
        Ok(())
    }

    /// PWD BASE64
    /// Application number: 707764'
    /// The derivation path format is: m/83696968'/707764'/{pwd_len}'/{index}'
    /// 20 <= pwd_len <= 86
    ///
    #[ignore = "pre test"]
    #[test]
    fn pre_test_to_pwd() -> Result<(), bitcoin::bip32::Error> {
        const PWD_LEN: usize = 21;
        let path = format!("m/83696968'/707764'/{PWD_LEN}'/0'");
        const DERIVED_ENTROPY: &str = "74a2e87a9ba0cdd549bdd2f9ea880d554c6c355b08ed25088cfa88f3f1c4f74632b652fd4a8f5fda43074c6f6964a3753b08bb5210c8f5e75c07a4c2a20bf6e9";
        const PWD: &str = "dKLoepugzdVJvdL56ogNV";
        let data = master_derive(&path)?;
        assert_eq!(data.to_lower_hex_string(), DERIVED_ENTROPY);
        let mut pwd = bitcoin::base64::prelude::BASE64_STANDARD.encode(&data);
        pwd.truncate(PWD_LEN);
        assert_eq!(pwd, PWD);
        Ok(())
    }
}
