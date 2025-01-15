use bitcoin::{
    bip32::{self, DerivationPath, Xpriv, Xpub},
    key::Secp256k1,
    Address, CompressedPublicKey, NetworkKind,
};
use std::str::FromStr;

/// BIP49 Derivation for Xpriv
///
/// Derivation scheme for P2WPKH-nested-in-P2SH based accounts.
///
/// see: [BIP49 spec](https://bips.dev/49/)
///
/// # Examples
/// ```
/// use artimonist::{BIP49, Xpriv, Error};
/// # use std::str::FromStr;
///
/// let master = Xpriv::from_str("xprv9s21ZrQH143K2sW69WDMTge7PMoK1bfeMy3cpNJxfSkqpPsU7DeHZmth8Sw7DVV2AMbC4jR3fKKgDEPJNNvsqhgTfyZwmWj439MWXUW5U5K")?;
/// let (addr, priv_key) = master.bip49_wallet(0, 12)?;
///
/// assert_eq!((addr.as_str(), priv_key.as_str()), ("32d3TaqdGccbDpu9L5R5vvGHQDnAPGfZea", "L1EDBwkRwzxwc6cufANuNWCwQFhBUXmD4o8dDz2w4pDEpRFM2Tma"));
///
/// # Ok::<(), artimonist::Error>(())
/// ```

// # Reference
// [1] - [BIP49 spec](https://bips.dev/49/)
// [2] - [Ref website](https://iancoleman.io/bip39/)
//
pub trait Derivation {
    /// # Returns
    ///   (xpub, xpriv)
    fn bip49_account(&self, index: u32) -> Bip49Result;

    /// # Returns
    ///   (address, private_key)
    fn bip49_wallet(&self, account: u32, index: u32) -> Bip49Result;
}

type Bip49Result<T = (String, String)> = Result<T, bip32::Error>;

impl Derivation for Xpriv {
    fn bip49_account(&self, account: u32) -> Bip49Result {
        let secp = Secp256k1::default();
        let path = format!("m/49'/0'/{account}'");
        let xprv = self.derive_priv(&secp, &DerivationPath::from_str(&path)?)?;
        let xpub = Xpub::from_priv(&secp, &xprv);
        Ok((xpub.to_string(), xprv.to_string()))
    }

    fn bip49_wallet(&self, account: u32, index: u32) -> Bip49Result {
        let path = format!("m/49'/0'/{account}'/0/{index}'");
        let secp = Secp256k1::default();
        let xpriv = self.derive_priv(&secp, &DerivationPath::from_str(&path)?)?;
        let private_key = xpriv.to_priv();
        let pub_key = CompressedPublicKey::from_private_key(&secp, &private_key).expect("pub_key");
        let address = Address::p2shwpkh(&pub_key, NetworkKind::Main);
        Ok((address.to_string(), private_key.to_wif()))
    }
}

#[cfg(test)]
mod bip44_test {
    use super::*;
    use bitcoin::base58;
    use bitcoin::hex::FromHex;
    use std::fmt;

    struct Ypriv(Xpriv);
    /// Version bytes for extended private keys on the Bitcoin network.
    const BIP49_VERSION_BYTES_MAINNET_PRIVATE: [u8; 4] = [0x04, 0x9d, 0x78, 0x78];
    /// Version bytes for extended public keys on the Bitcoin network.
    // const BIP49_VERSION_BYTES_MAINNET_PUBLIC: [u8; 4] = [0x04, 0x9d, 0x7c, 0xb2];

    impl fmt::Display for Ypriv {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let data = [&BIP49_VERSION_BYTES_MAINNET_PRIVATE, &self.0.encode()[4..]].concat();
            base58::encode_check_to_fmt(f, &data[..])
        }
    }

    /// # Reference
    ///     <https://iancoleman.io/bip39>
    #[test]
    fn test_bip49_master() -> Result<(), bip32::Error> {
        const TEST_DATA: &[[&str; 4]] = &[
          ["36b0d3535aa764d3b33a82241211c5685283918e068e8141f0038a1f0882805f013e102689ecffe25e3e7a6b69540ffb927be0775ec2c1af5052d347e6847342",
          "yprvABrGsX5C9jant1emhiUjqrmH9a9wbmRL88mSwZXEZQFn5jnvkp3Avnu6vtJgpxfSEuoVmnWcn7ijm2WDgqnguxpPPMPobZT7vcqunotD7Xr",
          "yprvAJSnjRQ7JFNuoJW4Ab6eb8oAHUAJ9vJdETq3PnxZBwHeEvnCh22247dS8NC8RoWgGuDMmKKGHtAV7jmaeeUJ9gzYZkwA5rQNgWxPB2eiiVQ",
          "ypub6XS98vw18cwD1naXGcdexGjtqVznZP2UbgkeCBNAkGpd7j7MEZLGbuwuyfCAstNRCLEA8P2FBG9XpLstG4ubGn3hQAKsnV7j2CnEBsCWuAW"],
        ];
        for x in TEST_DATA {
            let master = Xpriv::new_master(NetworkKind::Main, &Vec::from_hex(x[0]).expect("seed"))?;
            assert_eq!(Ypriv(master).to_string(), x[1]);
            let (_, xpriv) = master.bip49_account(0)?;
            let ypriv = Ypriv(Xpriv::from_str(&xpriv)?);
            assert_eq!(ypriv.to_string(), x[2]);
        }
        Ok(())
    }

    #[test]
    fn test_bip49_account() -> Result<(), bip32::Error> {
        const TEST_DATA: &[[&str; 3]] = &[
        ["xprv9s21ZrQH143K2k5PPw697AeKWWdeQueM2JCKu8bsmF7M7dDmPGHecHJJNGeujWTJ97Fy9PfobsgZfxhcpWaYyAauFMxcy4fo3x7JNnbYQyD",
        "xpub6C84nZSWyfEQWFeiPT5bWhBvPvk6UsdNiYTsP47fqFQKxntSs6R7oJodKxnE5bSLNBr2q4ZPmWvSwxNEqKk4sgXJwEawgMMSnkJJ5CzZyv1",
        "xprv9y8iP3ud9Hg7HmaFHRYb9ZFBqtuc5QuXMKYGafi4GusM5zZJKZ6sFWV9UiYmJA5xrZcWXqF25AxAfBFA8ZBCmJY4FiPTErsGw3jjNHwKkgb"],
        ["xprv9s21ZrQH143K2sW69WDMTge7PMoK1bfeMy3cpNJxfSkqpPsU7DeHZmth8Sw7DVV2AMbC4jR3fKKgDEPJNNvsqhgTfyZwmWj439MWXUW5U5K",
        "xpub6CGaEEgcBxtN1jcD2mkpQh9JAKwKqG4MXWxC7SrY8AATitVTvLomWakBcW3zwwizPx6dS8MuypiQ2zTUGSW2t7wQ88hz5JhxuLerijnwHhk",
        "xprv9yHDpj9iMbL4oFXjvkDp3ZCZcJ6qRoLWAJ2bK4SvZpdUr6AKNoVWxnRhmG4WXJ74AR8jkDVSDuomNcqroNoJNiKgt2HDJ7WR9qk9xym1B3y"],
      ];
        for x in TEST_DATA {
            let root = Xpriv::from_str(x[0])?;
            assert_eq!(root.bip49_account(0)?, (x[1].to_owned(), x[2].to_owned()));
        }
        Ok(())
    }

    #[test]
    fn test_bip49_wallet() -> Result<(), bip32::Error> {
        const MASTER_KEY: &str = "xprv9s21ZrQH143K2sW69WDMTge7PMoK1bfeMy3cpNJxfSkqpPsU7DeHZmth8Sw7DVV2AMbC4jR3fKKgDEPJNNvsqhgTfyZwmWj439MWXUW5U5K";
        const TEST_DATA: &[(u32, &str, &str)] = &[
            (
                0,
                "3K8UonLxbWyW8EyHFptZyHrpniacgB8XqE",
                "KxHy22XMaogA281whsRH4SSuv5yEU73rra1uhrULBgGtbBtAphKJ",
            ),
            (
                6,
                "3MriKs9SD8ZvBVBAVYuJgk51sDxqJ1Ua5i",
                "L3Nm8SZmuPcQ6s1Gw5EjH6dx8cp9bARdLwmvWdoyyg9wtzRXq2Ax",
            ),
            (
                18,
                "3KfnGuXmfPYveKMfzR8DXC7u5FDg5SYyDu",
                "KzsWtUr8KHutyJ5VbrJuroiU36DGgGoWV7dvEMi4s1ogrbzj1i3H",
            ),
        ];
        let root = Xpriv::from_str(MASTER_KEY)?;
        for x in TEST_DATA {
            assert_eq!(root.bip49_wallet(0, x.0)?, (x.1.to_owned(), x.2.to_owned()));
        }
        Ok(())
    }
}
