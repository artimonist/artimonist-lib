#![warn(missing_docs)]
//! # Artimonist
//!
//! `Artimonist` is a chart-based tool for creating mnemonics.
//!
//! Try the live web page: <https://www.artimonist.org>
//!
//! # Examples
//! ```
//! use artimonist::{Diagram, SimpleDiagram, BIP85, Language};
//!
//! let items = vec![Some('🍔'), Some('🍟'), Some('🌭'), Some('🍦'), Some('🍩')];
//! let indices = vec![(1, 1), (5, 5), (1, 5), (5, 1), (3, 3)];
//!
//! let diagram = SimpleDiagram::from_items(items, &indices)?;
//! let master = diagram.to_master("🚲🍀🌈".as_bytes())?;
//! let mnemonic = master.bip85_mnemonic(Language::English, 15, 0).unwrap();
//!
//! assert_eq!(&mnemonic, "lake album jump occur hedgehog fantasy drama sauce oyster velvet gadget control behave hamster begin");
//! # Ok::<(), artimonist::Error>(())
//! ```

pub(crate) mod bip38;
pub(crate) mod bip39;
pub(crate) mod bip49;
pub(crate) mod bip85;
pub(crate) mod bit_operation;
pub(crate) mod complex;
pub(crate) mod diagram;
pub(crate) mod password;
pub(crate) mod simple;
pub(crate) mod words;

pub use bip38::Encryptor;
pub use bip39::Derivation as BIP39;
pub use bip49::Derivation as BIP49;
pub use bip85::{Derivation as BIP85, Language, PasswordType as Password};
#[doc(no_inline)]
pub use bitcoin::{self, bip32::Xpriv};
pub use complex::ComplexDiagram;
pub use diagram::Diagram;
pub use simple::SimpleDiagram;

///
/// Global error definition
///
pub mod error {
    pub use super::bip38::EncryptError;
    pub use super::bip85::DeriveError;
    pub use super::bitcoin::bip32::Error as Bip32Error;
    pub use super::diagram::DiagramError;

    use thiserror::Error;

    /// Artimonist Error
    #[derive(Error, Debug, PartialEq)]
    pub enum Error {
        /// Diagram Error
        #[error("diagram error")]
        DiagramError(#[from] DiagramError),
        /// Encrypt Error
        #[error("encrypt error")]
        EncryptError(#[from] EncryptError),
        /// Bip85 Error
        #[error("bip85 error")]
        Bip85Error(#[from] DeriveError),
        /// Bip32 Error
        #[error("bip32 error")]
        Bip32Error(#[from] Bip32Error),
    }

    /// Artimonist Result
    pub type ArtResult<T = ()> = Result<T, Error>;
}

pub use error::Error;
