pub use super::{bit_operation::BitOperation, password::PasswordType, words::Language};
use bitcoin::{
    bip32::{ChainCode, ChildNumber, Xpriv},
    hashes::{hmac, sha256, sha512, Hash, HashEngine},
    hex::DisplayHex,
    secp256k1::SecretKey,
    NetworkKind,
};
use std::str::FromStr;
use thiserror::Error;

/// BIP85 Derivation for Xpriv
///
/// Deterministic Entropy From BIP32 Keychains.
///
/// see: [BIP85 spec](https://bips.dev/85/)
///
/// # Examples
/// ```
/// use artimonist::{BIP85, Xpriv, Password};
/// # use std::str::FromStr;
///
/// let master = Xpriv::from_str("xprv9s21ZrQH143K2sW69WDMTge7PMoK1bfeMy3cpNJxfSkqpPsU7DeHZmth8Sw7DVV2AMbC4jR3fKKgDEPJNNvsqhgTfyZwmWj439MWXUW5U5K")?;
///
/// assert_eq!(master.bip85_wif(3)?, "L43Bwws5GvHAtct3RqBg5A3JbJmoLrLGohLWDyizaXwh7ucSH6xd");
/// assert_eq!(master.bip85_xpriv(0)?, "xprv9s21ZrQH143K4AAZnirHuLg8Bq1Q8ozezrJjhyYhF2ZJqDC5qbs1XMCggai5xFrgabXtyyERCAS4k6tiKbe42PRYPP32BN9xgxPP1rv7tSv".to_owned());
/// assert_eq!(master.bip85_pwd(Password::Distinct, 28, 50)?, "1bJc8dXiPh#&q$qHR$SBNiPxKBfU");
/// assert_eq!(master.bip85_pwd(Password::Emoji, 20, 100)?, "⏰🍟☕👍🎁🍉🔑👍💪🚗🎈🎄🎄🏆🍦👽🐵🍕🔒🍦");
///
/// # Ok::<(), artimonist::Error>(())
/// ```

// # Reference
// [1] - [BIP85 spec](https://bips.dev/85/)
// [2] - [Ref impl](https://github.com/rikitau/rust-bip85)
//
#[allow(unused)]
pub trait Derivation {
    /// Mnemonic words  
    // Path format is: m/83696968'/39'/{language}'/{words}'/{index}'
    ///
    /// # Parameters
    ///   lang: Language in [0 ~ 9]  
    ///   count: words count in [12, 15, 18, 21, 24]  
    ///   index: 0 ~ 2^31  
    ///
    /// # Return
    ///   mnemonic words joined by ascii space
    fn bip85_mnemonic(&self, lang: Language, count: u32, index: u32) -> DeriveResult<String>;

    /// mnemonic list of [24, 21, 18, 15, 12] words from one entropy  
    // Path format is: m/83696968'/39'/{language}'/24'/{index}'
    fn bip85_mnemonic_list(&self, lang: Language, index: u32) -> DeriveResult<[String; 5]>;

    /// HD-Seed WIF  
    // Path format is m/83696968'/2'/{index}'
    fn bip85_wif(&self, index: u32) -> DeriveResult<String>;

    /// XPRV  
    // Path format is m/83696968'/32'/{index}'
    fn bip85_xpriv(&self, index: u32) -> DeriveResult<String>;

    /// PWD BASE64  
    // Path format is: m/83696968'/707764'/{pwd_len}'/{index}'
    /// 20 <= pwd_len <= 86
    fn bip85_pwd(&self, typ: PasswordType, pwd_len: usize, index: u32) -> DeriveResult<String>;
}

/// BIP85 Derivation
fn bip85_derive(root: &Xpriv, path: &str) -> DeriveResult<[u8; 64]> {
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let path = bitcoin::bip32::DerivationPath::from_str(path)?;
    let derived = root.derive_priv(&secp, &path)?;

    let mut hmac = hmac::HmacEngine::<sha512::Hash>::new("bip-entropy-from-k".as_bytes());
    hmac.input(&derived.private_key.secret_bytes());
    let data = hmac::Hmac::from_engine(hmac).to_byte_array();
    Ok(data)
}

impl Derivation for Xpriv {
    fn bip85_mnemonic(&self, lang: Language, count: u32, index: u32) -> DeriveResult<String> {
        if !matches!(count, 12 | 15 | 18 | 21 | 24) {
            return Err(DeriveError::InvalidParameter("count"));
        }
        let (count, index) = (count as usize, index as usize);

        let data = {
            let path = format!("m/83696968'/39'/{}'/{count}'/{index}'", lang as u32);
            let entropy = bip85_derive(self, &path)?[..(count * 4 / 3)].to_vec(); // truncate
            let check = sha256::Hash::hash(&entropy).as_byte_array()[0];
            [entropy, vec![check]].concat()
        };

        Ok(data
            .bit_chunks(11)
            .take(count)
            .map(|i| lang.get_word(i as usize).unwrap())
            .collect::<Vec<_>>()
            .join(" "))
    }

    fn bip85_mnemonic_list(&self, lang: Language, index: u32) -> DeriveResult<[String; 5]> {
        let path = format!("m/83696968'/39'/{}'/24'/{index}'", lang as u32); // use max len: 24
        let raw_entropy = bip85_derive(self, &path)?;
        Ok([24, 21, 18, 15, 12].map(|n| {
            let data = {
                let entropy = &raw_entropy[..(n * 4 / 3)]; // truncate
                let check = sha256::Hash::hash(&entropy).as_byte_array()[0];
                [entropy, &[check]].concat()
            };
            // split to indices, map to words, join to string.
            data.bit_chunks(11)
                .take(n)
                .map(|i| lang.get_word(i as usize).unwrap())
                .collect::<Vec<_>>()
                .join(" ")
        }))
    }

    fn bip85_wif(&self, index: u32) -> DeriveResult<String> {
        let path = format!("m/83696968'/2'/{index}'");
        let entropy = bip85_derive(self, &path)?;
        let priv_key = bitcoin::PrivateKey::from_slice(&entropy[..32], NetworkKind::Main)?;
        Ok(priv_key.to_wif())
    }

    fn bip85_xpriv(&self, index: u32) -> DeriveResult<String> {
        let path = format!("m/83696968'/32'/{index}'");
        let entropy = bip85_derive(self, &path)?;
        let chain_code = ChainCode::from_hex(&entropy[..32].to_lower_hex_string()).unwrap();
        let xpriv = Xpriv {
            network: NetworkKind::Main,
            depth: 0,
            parent_fingerprint: Default::default(),
            child_number: ChildNumber::Normal { index: 0 },
            private_key: SecretKey::from_slice(&entropy[32..])?,
            chain_code,
        };
        Ok(xpriv.to_string())
    }

    fn bip85_pwd(
        &self,
        pwd_type: PasswordType,
        pwd_len: usize,
        index: u32,
    ) -> DeriveResult<String> {
        if pwd_len < 20 || 86 < pwd_len {
            return Err(DeriveError::InvalidParameter("20 <= pwd_len <= 86"));
        }
        let path = format!("m/83696968'/707764'/{pwd_len}'/{index}'");
        let entropy = bip85_derive(self, &path)?;
        Ok(entropy
            .bit_chunks(6)
            .take(pwd_len)
            .map(|v| pwd_type.get_char(v as usize).unwrap())
            .collect::<String>())
    }
}

/// Derive error
#[derive(Error, Debug, PartialEq)]
pub enum DeriveError {
    /// Invalid parameter
    #[error("invalid parameter: {0}")]
    InvalidParameter(&'static str),
    /// Invalid derive path
    #[error("invalid derive path")]
    InvalidPath(#[from] bitcoin::bip32::Error),
    /// Secp error
    #[error("runtime error")]
    RuntimeError(#[from] bitcoin::secp256k1::Error),
}

pub(crate) type DeriveResult<T = ()> = Result<T, DeriveError>;

#[cfg(test)]
mod bip85_test {
    use super::*;
    use bitcoin::hex::DisplayHex;

    #[test]
    fn test_bip85_mnemonic() -> DeriveResult {
        {
            // PATH m/83696968'/39'/0'/18'/0';
            const MASTER_KEY: &str = "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb";
            const DERIVED_MNEMONIC: &str = "near account window bike charge season chef number sketch tomorrow excuse sniff circle vital hockey outdoor supply token";
            let master = bitcoin::bip32::Xpriv::from_str(MASTER_KEY)?;
            let mnemonic = master.bip85_mnemonic(Language::English, 18, 0)?;
            assert_eq!(mnemonic, DERIVED_MNEMONIC);
        }
        {
            // PATH: m/83696968'/39'/0'/24'/0'
            const MASTER_KEY: &str = "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb";
            const DERIVED_MNEMONIC: &str = "puppy ocean match cereal symbol another shed magic wrap hammer bulb intact gadget divorce twin tonight reason outdoor destroy simple truth cigar social volcano";
            let master = bitcoin::bip32::Xpriv::from_str(MASTER_KEY)?;
            let mnemonics = master.bip85_mnemonic_list(Language::English, 0)?;
            assert_eq!(mnemonics[0], DERIVED_MNEMONIC);
        }

        Ok(())
    }

    #[test]
    fn test_bip85_wif() -> DeriveResult {
        // PATH: m/83696968'/2'/0';
        const MASTER_KEY: &str = "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb";
        const DERIVED_WIF: &str = "Kzyv4uF39d4Jrw2W7UryTHwZr1zQVNk4dAFyqE6BuMrMh1Za7uhp";
        let master = bitcoin::bip32::Xpriv::from_str(MASTER_KEY)?;
        let priv_key = master.bip85_wif(0)?;
        assert_eq!(priv_key, DERIVED_WIF);
        Ok(())
    }

    #[test]
    fn test_bip85_xpriv() -> DeriveResult {
        // PATH: m/83696968'/32'/0'
        const MASTER_KEY: &str = "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb";
        const DERIVED_XPRV: &str = "xprv9s21ZrQH143K2srSbCSg4m4kLvPMzcWydgmKEnMmoZUurYuBuYG46c6P71UGXMzmriLzCCBvKQWBUv3vPB3m1SATMhp3uEjXHJ42jFg7myX";
        let master = bitcoin::bip32::Xpriv::from_str(MASTER_KEY)?;
        let xpriv = master.bip85_xpriv(0)?;
        assert_eq!(xpriv, DERIVED_XPRV);
        Ok(())
    }

    #[test]
    fn test_bip85_pwd() -> DeriveResult {
        // PATH: m/83696968'/707764'/21'/0'
        const MASTER_KEY: &str = "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb";
        const DERIVED_PWD: &str = "dKLoepugzdVJvdL56ogNV";
        let root = bitcoin::bip32::Xpriv::from_str(MASTER_KEY)?;
        let pwd = root.bip85_pwd(PasswordType::Legacy, 21, 0)?;
        assert_eq!(pwd, DERIVED_PWD);
        Ok(())
    }

    /// test bip85 derivation
    /// # Reference
    ///   <https://bips.dev/85/>
    #[test]
    #[ignore = "pre test"]
    fn test_bip85_derivation() -> Result<(), bitcoin::bip32::Error> {
        const MASTER_BIP32_ROOT_KEY: &str = "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb";
        const PATH: &str = "m/83696968'/0'/0'";
        const DERIVED_KEY: &str =
            "cca20ccb0e9a90feb0912870c3323b24874b0ca3d8018c4b96d0b97c0e82ded0";
        const DERIVED_ENTROPY: &str = "efecfbccffea313214232d29e71563d941229afb4338c21f9517c41aaa0d16f00b83d2a09ef747e7a64e8e2bd5a14869e693da66ce94ac2da570ab7ee48618f7";

        let secp = bitcoin::secp256k1::Secp256k1::new();
        let master = bitcoin::bip32::Xpriv::from_str(MASTER_BIP32_ROOT_KEY)?;
        let path = bitcoin::bip32::DerivationPath::from_str(PATH)?;
        let derived = master.derive_priv(&secp, &path)?;
        let derived_key = derived.private_key.secret_bytes().to_lower_hex_string();
        assert_eq!(derived_key, DERIVED_KEY);

        let mut hmac = hmac::HmacEngine::<sha512::Hash>::new("bip-entropy-from-k".as_bytes());
        hmac.input(&derived.private_key.secret_bytes());
        let data = hmac::Hmac::from_engine(hmac).to_byte_array();
        assert_eq!(data.to_lower_hex_string(), DERIVED_ENTROPY);

        Ok(())
    }

    /// test japanese mnemonic to seed
    /// # Reference
    ///   <https://iancoleman.io/bip39/#japanese>
    #[test]
    #[ignore = "pre test"]
    fn test_japanese_mnemonic_to_seed() {
        const JPAN_WORDS: &str = "すおどり　ひびく　はんこ　しはい　しみん　こたえる　しあわせ　たいいん　えいせい　こそだて　ひかく　とつにゅう　えんぜつ　うけつけ　せんよう";
        const BIP39_SEED: &str = "6059453e22e4fe02ddc75df607e53194d432e2838b20ae82a16f550f16e64869a9b0a3cda1dbadaf2febceceb5ec0fdf66fb0198306159411f3e2501de048ea7";

        let words = JPAN_WORDS.replace('　', " "); // replace to ascii space
        let mut mac = crypto::hmac::Hmac::new(crypto::sha2::Sha512::new(), words.as_bytes());
        let salt = "mnemonic";
        let mut output: [u8; 64] = [0; 64];
        crypto::pbkdf2::pbkdf2(&mut mac, salt.as_bytes(), u32::pow(2, 11), &mut output);
        assert_eq!(output.to_lower_hex_string(), BIP39_SEED);
    }
}
