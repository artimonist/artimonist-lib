/*!
 * Tests WarpWallet implementation in Rust.
 *
 * WarpWallet is a deterministic bitcoin address generator.
 *    You never have to save or store your private key anywhere.
 *    Just pick a really good password - many random words,
 *    for example - and never use it for anything else.
 *
 * WarpWallet adds two improvements:
 *    (1) WarpWallet uses scrypt to make address generation both memory and time-intensive.
 *    (2) you can "salt" your passphrase with your email address.
 *    Though salting is optional, we recommend it.
 *    Any attacker of WarpWallet addresses would have to target you individually,
 *    rather than netting you in a wider, generic sweep. And your email is trivial to remember,
 *    so why not?
 *
 *  ```
 *  s1	=	scrypt(key=(passphrase||0x1), salt=(salt||0x1), N=2^18, r=8, p=1, dkLen=32)
 *  s2	=	pbkdf2(key=(passphrase||0x2), salt=(salt||0x2), c=2^16, dkLen=32, prf=HMAC_SHA256)
 *  keypair	=	generate_bitcoin_keypair(s1 ⊕ s2)
 *  ```
 *
 *  # References
 *  [1] - The original Warpwallet website.
 *        https://keybase.io/warp
 *
 *  [2] - Go implementation of the WarpWallet algorithm.
 *        https://github.com/ellisonch/warpwallet
 *        https://github.com/aiportal/warpwallet
 *
 *  # Examples
 *  ```
 *  cargo test --release
 *  ```
 */
use bitcoin::{
    base58,
    hashes::{sha256, Hash},
    hex::DisplayHex,
    key::Secp256k1,
    Address, Network, PrivateKey,
};
use crypto::scrypt;
use crypto::{hmac::Hmac, pbkdf2::pbkdf2, sha2::Sha256};

#[cfg(test)]
mod pre_test_warp_wallet {
    use super::*;

    #[ignore = "pre test"]
    #[test]
    fn pre_test_warp_wallet() {
        for td in WARP_TEST_DATA {
            let [pass_phrase, salt, seed_str, priv_str, address] = *td;

            // warp seed
            let s1 = {
                let password = [pass_phrase.as_bytes(), &[1u8]].concat();
                let salt = [salt.as_bytes(), &[1u8]].concat();
                let mut output: [u8; 32] = [0; 32];
                let param = scrypt::ScryptParams::new(18, 8, 1);
                scrypt::scrypt(&password, &salt, &param, &mut output);
                output
            };
            let s2 = {
                let password = [pass_phrase.as_bytes(), &[2u8]].concat();
                let salt = [salt.as_bytes(), &[2u8]].concat();
                let mut mac = Hmac::new(Sha256::new(), &password);
                let mut output: [u8; 32] = [0; 32];
                pbkdf2(&mut mac, &salt, u32::pow(2, 16), &mut output);
                output
            };
            let mut secret = s1;
            secret
                .iter_mut()
                .zip(s2.iter())
                .for_each(|(a, b)| *a = *a ^ b);
            assert_eq!(seed_str, secret.to_lower_hex_string());

            // private key
            let key = [&[0x80u8][..], &secret].concat();
            let sum = sha256::Hash::hash(&key)
                .hash_again()
                .to_byte_array()
                .first_chunk::<4>()
                .unwrap()
                .clone();
            let key = [&key[..], &sum[..]].concat();
            assert_eq!(base58::encode(&key), priv_str);

            // address
            let pub_key = PrivateKey::from_wif(priv_str)
                .expect("priv_key")
                .public_key(&Secp256k1::new());
            let addr = Address::p2pkh(pub_key, Network::Bitcoin);
            assert_eq!(addr.to_string(), address);
        }
    }

    const WARP_TEST_DATA: &[[&str; 5]] = &[
        [
            "12345678",
            "123",
            "d6353d60676961cce43cdedd379b3d3dc170f307d617622102c9f78a1ce19d97",
            "5KSdEg19wJ8JmUiaKPYAa1T46e9fVtmpbW9MJr8PDbF5KwRwrsn",
            "1Gh488CdSgknBqS6vtTBMTMJhq9CyTcmbY",
        ],
        [
            "abcdefg",
            "abc",
            "6f56cd2fe0407420ab1e0d04db8c91aeea549c36a697f24c8a77c756b775bac0",
            "5JfKb6ESxwCJaBeFc77GnbP8Y1L1oa3LHDW6ZYrmad3yWaUf1Da",
            "1BdW4budNtbVmmABsb56UjGokp7PgobMuE",
        ],
        [
            "觉壤罩冠败豪漏玉友和好排市乏焰",
            "测试123",
            "629b3c2080f28293c5bd4c59b97319aa4fe7caa0e8d1b32e7ec3bf3d4206d875",
            "5JZiMDJYARLvXHwwxQxuL6zfTTMsvjVTYKUTy2fgNb8JpDZCtCh",
            "15Cj8JEJERQXgF1XB8fE8Y4pQa35oLnJHA",
        ],
    ];
}
