/*!
 * # Reference
 *
 * [1] - Unicode characters
 *      <https://www.unicodepedia.com/>
 *
 * # Descriptions
 *
 * [1] - Simple Diagram secret data construction
 *      |--utf8 chars---|-7 bytes-|-1 byte-|
 *      |Char1|Char2|...| Indices |CheckSum|
 *      |---------------|---------|--------|
 *      n = indices.count_ones()  (version == 0)
 *
 * [2] - Simple Diagram indices data construction
 *      0b0xxx_xxxx
 *      0b0xxx_xxxx
 *      0b0xxx_xxxx
 *      0b0xxx_xxxx
 *      0b0xxx_xxxx
 *      0b0xxx_xxxx
 *      0b0xxx_xxxx
 *      x bits indices string position in diagram.
**/
use super::diagram::*;
use bitcoin::hashes::{sha256, Hash};

/// Simple Diagram
///
/// `Simple Diagram' contains arbitrary characters in 7 * 7 grid cells.
/// All Unicode characters are supported.
///
/// # Examples
/// ```
/// # use artimonist::{Diagram, SimpleDiagram};
/// # use bitcoin::hex::DisplayHex;
/// let mut diagram = SimpleDiagram::new();
/// diagram.set(Some('🐶'), 2, 1);
/// diagram.set(Some('☕'), 3, 6);
///
/// let entropy = diagram.to_entropy("🎄🎈🔑".as_bytes())?;
/// assert_eq!(entropy.to_lower_hex_string(), "8402af95a4caa79b9ac7663077c23500a82c4ba4754e1d937e0d53e42e463e36");
/// # Ok::<(), artimonist::Error>(())
/// ```
///
#[derive(Debug)]
pub struct SimpleDiagram {
    data: [[Option<char>; 7]; 7],
}

impl Diagram for SimpleDiagram {
    type Item = Option<char>;

    /// create empty Diagram
    fn new() -> Self {
        SimpleDiagram {
            data: [[None; 7]; 7],
        }
    }

    /// if all cells is empty, return true.  
    /// empty diagram is invalid to generate secret data  
    fn is_empty(&self) -> bool {
        self.data.iter().all(|row| row.iter().all(|v| v.is_none()))
    }

    /// restore diagram from chars and indices  
    /// indices: chars position of (row, col) format
    fn from_items(mut items: Vec<Self::Item>, indices: &[(usize, usize)]) -> DiagramResult<Self> {
        if items.is_empty() || items.iter().any(|v| v.is_none()) {
            return Err(DiagramError::InvalidParameter(
                "items cannot contains none value.",
            ));
        }
        if indices.is_empty() || indices.len() != items.len() {
            return Err(DiagramError::InvalidParameter(
                "indices len should equal to items len.",
            ));
        }
        // fill diagram
        let mut data = [[None; 7]; 7];
        items.reverse();
        indices.iter().for_each(|&(row, col)| {
            data[row][col] = items.pop().unwrap_or_default();
        });
        Ok(SimpleDiagram { data })
    }

    /// get char at diagram position
    /// # Panics
    /// row >= 7 || col >= 7  
    fn get(&self, row: usize, col: usize) -> Option<&Self::Item> {
        match self.data[row][col].is_some() {
            true => Some(&self.data[row][col]),
            false => None,
        }
    }

    /// write char to diagram  
    /// # Panics
    /// row >= 7 || col >= 7
    fn set(&mut self, val: Option<char>, row: usize, col: usize) -> DiagramResult<()> {
        self.data[row][col] = val;
        Ok(())
    }

    /// restore diagram from raw secret data
    fn from_secret(mut secret: Vec<u8>) -> DiagramResult<Self> {
        // must have content
        if secret.len() <= 8 {
            return Err(DiagramError::InvalidParameter("secret too short."));
        }
        // tail byte is checksum
        if let Some(check) = secret.pop() {
            if check != sha256::Hash::hash(&secret).as_byte_array()[0] {
                return Err(DiagramError::InvalidParameter("checksum fail."));
            }
        }

        // 7 bytes indices
        let indices: Vec<u8> = secret.split_off(secret.len() - 7);
        // check version
        if indices.iter().any(|v| v & VERSION_MASK != 0) {
            return Err(DiagramError::InvalidVersion);
        }

        // residue must be a valid UTF-8 string
        let s = String::from_utf8(secret)
            .or(Err(DiagramError::InvalidParameter("invalid utf8 chars.")))?;
        let mut items: Vec<Self::Item> = s.chars().map(|v| Some(v)).collect();

        // fill diagram
        let mut data = [[None; 7]; 7];
        for row in (0..7).rev() {
            for col in (0..7).rev() {
                if indices[row] & INDICES_MASK[col] > 0 {
                    match items.pop() {
                        Some(Some(ch)) => data[row][col] = Some(ch),
                        _ => return Err(DiagramError::InvalidParameter("items len invalid.")),
                    }
                }
            }
        }
        if !items.is_empty() {
            return Err(DiagramError::InvalidParameter("items len invalid."));
        }
        Ok(SimpleDiagram { data })
    }

    /// generate raw secret data.
    fn to_secret(&self) -> DiagramResult<Vec<u8>> {
        if self.is_empty() {
            return Err(DiagramError::EmptyDiagram);
        }

        let mut chars = Vec::with_capacity(7 * 7);
        let mut indices = [0; 7];
        (0..7).for_each(|row| {
            (0..7).for_each(|col| {
                if let Some(ch) = self.data[row][col] {
                    chars.push(ch);
                    indices[row] |= INDICES_MASK[col];
                }
            });
        });

        let str = chars.into_iter().collect::<String>();
        let mut secret = [str.as_bytes(), &indices].concat();
        let check = sha256::Hash::hash(&secret).as_byte_array()[0];
        secret.push(check);

        Ok(secret)
    }
}

#[cfg(test)]
mod simple_diagram_test {
    use super::*;
    use bitcoin::hex::{DisplayHex, FromHex};

    #[test]
    fn test_simple_empty() {
        // empty diagram can't export secret data.
        let art = SimpleDiagram::new();
        assert!(art.to_secret().is_err());

        // empty secret data can't create diagram.
        let empty = vec![0; 8];
        assert!(SimpleDiagram::from_secret(empty).is_err());
    }

    #[test]
    fn test_simple_invalid() {
        const INVALID_SECRET_LEN: [u8; 8] = [0; 8];
        assert!(SimpleDiagram::from_secret(INVALID_SECRET_LEN.to_vec()).is_err());

        const INVALID_CHECKSUM: [u8; 9] = [b'A', 0, 0, 0, 0, 0, 0, 0, 0x14];
        assert!(SimpleDiagram::from_secret(INVALID_CHECKSUM.to_vec()).is_err());

        const INVALID_VERSION: [u8; 10] = [b'A', b'X', 0b1000_0001, 0, 0, 0, 0, 0, 0, 0x8d];
        assert!(SimpleDiagram::from_secret(INVALID_VERSION.to_vec())
            .is_err_and(|e| e == DiagramError::InvalidVersion));

        const INVALID_UTF8: [u8; 10] = [0xff, 0xef, 0, 0, 0, 0b000_1100, 0, 0, 0, 0x82];
        assert!(SimpleDiagram::from_secret(INVALID_UTF8.to_vec()).is_err());

        const INVALID_CHAR_COUNT: [u8; 10] = [b'A', b'X', 0, 0, 0, 0b000_1101, 0, 0, 0, 0xea];
        assert!(SimpleDiagram::from_secret(INVALID_CHAR_COUNT.to_vec()).is_err());

        const INVALID_CHAR_COUNT2: [u8; 10] = [b'A', b'X', 0, 0, 0, 0b000_0001, 0, 0, 0, 0x4b];
        assert!(SimpleDiagram::from_secret(INVALID_CHAR_COUNT2.to_vec()).is_err());

        let mut chars = vec![Some('A'), Some('Z')];
        // empty parameters
        assert!(SimpleDiagram::from_items(vec![], &[(1, 1)]).is_err());
        assert!(SimpleDiagram::from_items(chars.clone(), &[]).is_err());
        // indices count
        assert!(SimpleDiagram::from_items(chars.clone(), &[(1, 1)]).is_err());
        assert!(SimpleDiagram::from_items(chars.clone(), &[(1, 1), (2, 2), (3, 3)]).is_err());
        // empty str
        chars.push(None);
        assert!(SimpleDiagram::from_items(chars, &[(1, 1), (2, 2), (3, 3)]).is_err());
    }

    #[test]
    fn test_simple_secret() -> DiagramResult<()> {
        const CHARS_STR: &str = "A&*王😊";
        const CHARS_INDICES: &[(usize, usize)] = &[(0, 6), (1, 1), (1, 3), (4, 2), (6, 6)];
        const SECRET_HEX: &str = "41262ae78e8bf09f988a01280000100001ee";

        let mut art = SimpleDiagram::new();
        CHARS_INDICES
            .iter()
            .zip(CHARS_STR.chars())
            .for_each(|(&(row, col), ch)| art.set(Some(ch), row, col).unwrap_or_default());
        let indices: Vec<(usize, usize)> = art.indices().collect();
        assert_eq!(&indices, CHARS_INDICES);
        assert_eq!(art.to_secret()?.to_lower_hex_string(), SECRET_HEX);

        // from_raw
        let art = SimpleDiagram::from_secret(Vec::from_hex(SECRET_HEX).expect("TEST_SECRET_HEX"))?;
        let indices: Vec<(usize, usize)> = art.indices().collect();
        assert_eq!(&indices, CHARS_INDICES);
        assert_eq!(art.get(6, 6).unwrap_or(&None), &Some('😊'));
        assert_eq!(art.to_secret()?.to_lower_hex_string(), SECRET_HEX);
        Ok(())
    }

    #[test]
    fn test_simple_entropy() -> DiagramResult<()> {
        const RAW_SECRET_HEX: &str = "41262ae78e8bf09f988a012800001000406d";
        const WARP_ENTROPY: &str =
            "0948fd6d7b1dc397d26080804870913abc086636d3ed11d4fcb0f16f7c31a91a";
        const SALT_STR: &str = "123abc";
        const SALT_ENTROPY: &str =
            "e06ffd848c7901ca5757d848e5e81d69f9853273bee6772dcd25f56c506a1635";

        let secret = Vec::from_hex(RAW_SECRET_HEX).expect("RAW_SECRET_HEX");
        let art = SimpleDiagram::from_secret(secret)?;
        let entropy = art.to_entropy(Default::default())?;
        assert_eq!(entropy.to_lower_hex_string(), WARP_ENTROPY);

        let salt_entropy = art.to_entropy(SALT_STR.as_bytes())?;
        assert_eq!(salt_entropy.to_lower_hex_string(), SALT_ENTROPY);

        Ok(())
    }
}
