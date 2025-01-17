/*!
 * # Reference
 *
 * [1] - Unicode characters
 *      <https://www.unicodepedia.com/>
 *
 * # Descriptions
 *
 * [1] - Complex Diagram secret data construction
 *      |-----n segments----|-n bytes-|-7 bytes-|-1 byte-|
 *      |String1|String2|...|N1|N2|...| Indices |CheckSum|
 *      |-------------------|---------|---------|--------|
 *      n = indices.count_ones() - 1  (version == 1)
 *      N1,N2... is bytes count of String1,String2...
 *
 * [2] - Complex Diagram indices data construction
 *      0b1xxx_xxxx
 *      0b0xxx_xxxx
 *      0b0xxx_xxxx
 *      0b0xxx_xxxx
 *      0b0xxx_xxxx
 *      0b0xxx_xxxx
 *      0b0xxx_xxxx
 *      1 bit at top left corner is version of complex diagram.
 *      others x bits indices string position in diagram.
**/

use super::diagram::*;
use bitcoin::hashes::{sha256, Hash};

/// string chars count limit
pub const CELL_CHARS_LIMIT: usize = 50;

/// Complex Diagram
///
/// Complex diagram contains strings in 7 * 7 grid cells.
/// All UTF-8 strings with less than 50 characters are supported.
///
/// # Examples
/// ```
/// # use artimonist::{Diagram, ComplexDiagram};
/// # use bitcoin::hex::FromHex;
/// let secret = Vec::from_hex("414243313233e6b58be8af95e6b7b7413141262ae78e8bf09f988a030306050a8128000010000132").unwrap_or_default();
/// let mut diagram = ComplexDiagram::from_secret(secret)?;
///
/// assert_eq!(diagram.get(6, 6), Some(&"A&*王😊".to_owned()));
///
/// # Ok::<(), artimonist::Error>(())
/// ```
///
#[derive(Debug)]
pub struct ComplexDiagram {
    data: [[String; 7]; 7],
}

impl Diagram for ComplexDiagram {
    type Item = String;

    /// create empty diagram
    fn new() -> Self {
        let data = core::array::from_fn(|_| core::array::from_fn(|_| String::new()));
        ComplexDiagram { data }
    }

    /// if all cells is empty, return true.  
    fn is_empty(&self) -> bool {
        self.data.iter().all(|row| row.iter().all(|v| v.is_empty()))
    }

    /// restore diagram from strings and indices  
    /// indices: chars position of (row, col) format  
    fn from_items(mut items: Vec<String>, indices: &[(usize, usize)]) -> DiagramResult<Self> {
        if items.is_empty() || items.iter().any(|s| s.is_empty()) {
            return Err(DiagramError::InvalidParameter(
                "items cannot contains empty value.",
            ));
        }
        if indices.is_empty() || indices.len() != items.len() {
            return Err(DiagramError::InvalidParameter(
                "indices len should equal to items len.",
            ));
        }
        // fill diagram
        let mut diagram = Self::new();
        items.reverse();
        indices.iter().for_each(|&(row, col)| {
            diagram.data[row][col] = items.pop().unwrap_or_default();
        });
        Ok(diagram)
    }

    /// write string to diagram if str.chars().count() <= 50
    fn set(&mut self, str: String, row: usize, col: usize) -> DiagramResult<()> {
        if str.chars().count() > CELL_CHARS_LIMIT {
            return Err(DiagramError::Overflows("chars count <= 50"));
        }
        debug_assert!(str.len() < u8::MAX as usize);
        self.data[row][col] = str;
        Ok(())
    }

    /// get string from diagram  
    /// # Panics
    /// row >= 7 || col >= 7  
    fn get(&self, row: usize, col: usize) -> Option<&Self::Item> {
        match self.data[row][col].is_empty() {
            false => Some(&self.data[row][col]),
            true => None,
        }
    }

    /// create diagram from secret data
    fn from_secret(mut secret: Vec<u8>) -> DiagramResult<Self> {
        // must have content
        if secret.len() < 10 {
            return Err(DiagramError::InvalidParameter("secret too short.")); // invalid len
        }
        // tail byte is checksum
        if let Some(check) = secret.pop() {
            if check != sha256::Hash::hash(&secret).as_byte_array()[0] {
                return Err(DiagramError::InvalidParameter("checksum fail.")); // invalid checksum
            }
        }

        // tail 7 bytes is indices
        let indices: Vec<u8> = secret.split_off(secret.len() - 7);
        let (version, item_count) = indices
            .iter()
            .enumerate()
            .map(|(i, &v)| {
                (
                    (v & VERSION_MASK) >> (7 - i),
                    (v & INDICES_ALL).count_ones() as usize,
                )
            })
            .reduce(|(ver, count), (v, n)| (ver + v, count + n))
            .unwrap_or_default();
        if version != 1 {
            return Err(DiagramError::InvalidVersion); // invalid version
        }
        if item_count == 0 {
            return Err(DiagramError::InvalidParameter("indices is empty.")); // empty indices
        }

        // string lens
        let mut str_lens: Vec<u8> = secret.split_off(secret.len() - item_count);
        let (amount, has_zero) = str_lens
            .iter()
            .fold((0, false), |(a, z), &v| (a + v as usize, z || v == 0));
        if str_lens.is_empty() || has_zero || amount != secret.len() {
            return Err(DiagramError::InvalidParameter("str lens invalid.")); // invalid str lens
        }

        // fill data
        let mut diagram = ComplexDiagram::new();
        for row in (0..7).rev() {
            for col in (0..7).rev() {
                if indices[row] & INDICES_MASK[col] > 0 {
                    let n = str_lens.pop().unwrap_or_default();
                    let bs = secret.split_off(secret.len() - n as usize);
                    match String::from_utf8(bs) {
                        Ok(s) => diagram.data[row][col] = s,
                        Err(_) => {
                            return Err(DiagramError::InvalidParameter("invalid utf8 string."))
                        } // invalid utf8
                    }
                }
            }
        }
        Ok(diagram)
    }

    /// generate secret data  
    /// secret phrase composed by diagram strings, divisions, indices and checksum  
    /// if diagram is empty, return None  
    fn to_secret(&self) -> DiagramResult<Vec<u8>> {
        if self.is_empty() {
            return Err(DiagramError::EmptyDiagram);
        }

        let mut str_list: Vec<&str> = vec![];
        let mut str_lens: Vec<u8> = vec![];
        let mut indices: [u8; 7] = [0; 7];
        (0..7).for_each(|row| {
            (0..7).for_each(|col| {
                let s = &self.data[row][col];
                if s.is_empty() {
                    return;
                }
                debug_assert!(s.len() < u8::MAX as usize);
                str_list.push(s);
                str_lens.push(s.len() as u8);
                indices[row] |= INDICES_MASK[col];
            });
        });

        indices[0] |= VERSION_MASK; // version number of complex diagram
        let mut secret = [str_list.join("").as_bytes(), &str_lens[..], &indices[..]].concat();
        let check = sha256::Hash::hash(&secret).as_byte_array()[0];
        secret.push(check);

        Ok(secret)
    }
}

#[cfg(test)]
mod complex_diagram_test {
    use super::*;
    use bitcoin::hex::{DisplayHex, FromHex};

    #[test]
    fn test_complex_empty() {
        // empty diagram can't export secret data.
        let art = ComplexDiagram::new();
        assert!(art.to_secret().is_err());

        // empty secret data can't create diagram.
        let empty = vec![0; 8];
        assert!(ComplexDiagram::from_secret(empty).is_err());
    }

    #[test]
    fn test_complex_invalid() {
        const INVALID_SECRET_LEN: [u8; 9] = [0; 9];
        assert!(ComplexDiagram::from_secret(INVALID_SECRET_LEN.to_vec()).is_err());
        const INVALID_CHECKSUM: [u8; 10] = [b'A', 1, 0, 0, 0, 0, 0, 0, 0, 0xc5];
        assert!(ComplexDiagram::from_secret(INVALID_CHECKSUM.to_vec()).is_err());
        const INVALID_VERSION: [u8; 10] = [b'A', 1, 0, 0, 0, 0, 0, 0, 0, 0xc5];
        assert!(ComplexDiagram::from_secret(INVALID_VERSION.to_vec())
            .is_err_and(|e| e == DiagramError::InvalidVersion));
        const EMPTY_INDICES: [u8; 10] = [b'A', 1, 0b1000_0000, 0, 0, 0, 0, 0, 0, 0xce];
        assert!(ComplexDiagram::from_secret(EMPTY_INDICES.to_vec()).is_err());
        const INVALID_STR_LENS: [u8; 12] = [b'A', b'Z', 1, 2, 0b1000_0001, 0, 0, 0, 1, 0, 0, 0x82];
        assert!(ComplexDiagram::from_secret(INVALID_STR_LENS.to_vec()).is_err());
        const ZERO_STR_LENS: [u8; 12] = [b'A', b'Z', 0, 2, 0b1000_0001, 0, 0, 0, 1, 0, 0, 0x7e];
        assert!(ComplexDiagram::from_secret(ZERO_STR_LENS.to_vec()).is_err());
        const INVALID_UTF8: [u8; 12] = [0xff, b'Z', 1, 1, 0b1000_0001, 0, 0, 0, 1, 0, 0, 0x20];
        assert!(ComplexDiagram::from_secret(INVALID_UTF8.to_vec()).is_err());

        let mut strs = vec!["ABC".to_string(), "123".to_string()];
        // empty parameters
        assert!(ComplexDiagram::from_items(vec![], &[(1, 1)]).is_err());
        assert!(ComplexDiagram::from_items(strs.clone(), &[]).is_err());
        // indices count
        assert!(ComplexDiagram::from_items(strs.clone(), &[(1, 5)]).is_err());
        assert!(ComplexDiagram::from_items(strs.clone(), &[(0, 0), (0, 1), (1, 0)]).is_err());
        // empty str
        strs.push("".to_string());
        assert!(ComplexDiagram::from_items(strs, &[(0, 0), (0, 1), (1, 1)]).is_err());
    }

    #[test]
    fn test_complex_secret() {
        const STR_LIST: &[&str] = &["ABC", "123", "测试", "混A1", "A&*王😊"];
        const INDICES: &[(usize, usize)] = &[(0, 6), (1, 1), (1, 3), (4, 2), (6, 6)];
        const SECRET_HEX: &str =
            "414243313233e6b58be8af95e6b7b7413141262ae78e8bf09f988a030306050a8128000010000132";

        let mut diagram = ComplexDiagram::new();
        let success = INDICES
            .iter()
            .zip(STR_LIST)
            .all(|(&(row, col), &s)| diagram.set(s.to_owned(), row, col).is_ok());
        assert_eq!(success, true);
        let indices: Vec<(usize, usize)> = diagram.indices().collect();
        assert_eq!(&indices, INDICES);
        let secret = diagram.to_secret().unwrap_or_default();
        assert_eq!(secret.to_lower_hex_string(), SECRET_HEX);

        if let Ok(diagram) = ComplexDiagram::from_secret(secret) {
            assert_eq!(diagram.get(6, 6).unwrap_or(&String::new()), STR_LIST[4]);
            let indices: Vec<(usize, usize)> = diagram.indices().collect();
            assert_eq!(&indices, INDICES);
            let secret = diagram.to_secret().unwrap_or_default();
            assert_eq!(secret.to_lower_hex_string(), SECRET_HEX);
        } else {
            assert!(false, "from_secret() fail");
        }
    }

    #[test]
    fn test_complex_entropy() -> DiagramResult<()> {
        const SECRET_HEX: &str =
            "414243313233e6b58be8af95e6b7b7413141262ae78e8bf09f988a030306050a8128000010004052";
        const RAW_ENTROPY: &str =
            "f273657eb2394dbe4874571abf8d6f78b149bd86d1eec6c666509371e93004d3";
        const SALT_STR: &str = "123abc";
        const SALT_ENTROPY: &str =
            "3ff854b9f188d428068e3a9b7655d37795f1aaf1e6461b757f12935dee796bbf";

        let secret = Vec::from_hex(SECRET_HEX).expect("SECRET_HEX");
        let diag = ComplexDiagram::from_secret(secret)?;
        let entropy = diag.to_entropy(Default::default())?;
        assert_eq!(entropy.to_lower_hex_string(), RAW_ENTROPY);

        let salt_entropy = diag.to_entropy(SALT_STR.as_bytes())?;
        assert_eq!(salt_entropy.to_lower_hex_string(), SALT_ENTROPY);

        Ok(())
    }
}
