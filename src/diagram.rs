use bitcoin::{
    bip32::{self, Xpriv},
    NetworkKind,
};
use thiserror::Error;

pub(crate) const INDICES_MASK: [u8; 7] = [
    0b0100_0000,
    0b0010_0000,
    0b0001_0000,
    0b0000_1000,
    0b0000_0100,
    0b0000_0010,
    0b0000_0001,
];
pub(crate) const INDICES_ALL: u8 = 0b0111_1111;
pub(crate) const VERSION_MASK: u8 = 0b1000_0000;

/// # Diagram trait
///
/// `Diagram` is a 7 * 7 grid cells container.
///
pub trait Diagram {
    /// Items contained in the cell of a Diagram
    type Item;

    /// create empty Diagram
    fn new() -> Self;

    /// if all cells is empty, return true.
    fn is_empty(&self) -> bool;

    /// create diagram from items and indices
    fn from_items(items: Vec<Self::Item>, indices: &[(usize, usize)]) -> DiagramResult<Self>
    where
        Self: Sized;

    /// get diagram item
    fn get(&self, row: usize, col: usize) -> Option<&Self::Item>;

    /// set diagram item
    fn set(&mut self, value: Self::Item, row: usize, col: usize) -> DiagramResult<()>;

    /// restore diagram from secret data
    fn from_secret(secret: Vec<u8>) -> DiagramResult<Self>
    where
        Self: Sized;

    /// export diagram to secret data
    fn to_secret(&self) -> DiagramResult<Vec<u8>>;

    /// indices of non-empty elements formated to (row, col)
    fn indices(&self) -> impl Iterator<Item = (usize, usize)> {
        (0..7).flat_map(move |row| {
            (0..7).filter_map(move |col| self.get(row, col).map_or(None, |_| Some((row, col))))
        })
    }

    /// generate warp entropy  
    ///
    /// see:
    /// [warp wallet](https://keybase.io/warp),
    /// [go impl](https://github.com/ellisonch/warpwallet)
    fn to_entropy(&self, salt: &[u8]) -> DiagramResult<[u8; 32]> {
        let secret = self.to_secret()?;
        let mut s1 = {
            let secret = [secret.as_slice(), &[1u8]].concat();
            let salt = [salt, &[1u8]].concat();
            let mut output: [u8; 32] = [0; 32];
            let param = crypto::scrypt::ScryptParams::new(18, 8, 1);
            crypto::scrypt::scrypt(&secret, &salt, &param, &mut output);
            output
        };
        let s2 = {
            let secret = [secret.as_slice(), &[2u8]].concat();
            let salt = [salt, &[2u8]].concat();
            let mut output: [u8; 32] = [0; 32];
            let mut mac = crypto::hmac::Hmac::new(crypto::sha2::Sha256::new(), &secret);
            crypto::pbkdf2::pbkdf2(&mut mac, &salt, 65536, &mut output);
            output
        };
        s1.iter_mut().zip(s2.iter()).for_each(|(a, b)| *a = *a ^ b);
        Ok(s1)
    }

    /// generate extended private key
    fn to_master(&self, salt: &[u8]) -> DiagramResult<Xpriv> {
        let seed = self.to_entropy(salt)?;
        Ok(Xpriv::new_master(NetworkKind::Main, &seed)?)
    }
}

/// Diagram Error
#[derive(Error, Debug, PartialEq)]
pub enum DiagramError {
    /// Out of diagram 7 * 7 bounds
    #[error("out of bounds")]
    Overflows(&'static str),
    /// Invalid parameters
    #[error("invalid parameter: {0}")]
    InvalidParameter(&'static str),
    /// Invalid diagram version
    #[error("invalid diagram version")]
    InvalidVersion,
    /// Empty diagrams are not allowed to be exported
    #[error("diagram is empty")]
    EmptyDiagram,
    /// BIP32 error
    #[error("bip32 error")]
    Bip32Error(#[from] bip32::Error),
}

pub(crate) type DiagramResult<T = ()> = Result<T, DiagramError>;
