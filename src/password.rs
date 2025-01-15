/*! BIP85 Password characters
 *
 */

/// Password encode type
#[allow(unused)]
#[derive(Debug, Default)]
pub enum PasswordType {
    /// Standard Base64 characters
    Legacy, // legacy Base64
    /// Base58 add 6 common symbols
    #[default]
    Distinct, // "@#$%&*" + Base58
    /// Emoji password
    Emoji, // emoji characters
}

impl PasswordType {
    #[inline]
    pub(crate) fn get_char(&self, index: usize) -> Option<char> {
        match &self {
            PasswordType::Legacy => LEGACY_BYTES
                .get(index)
                .map_or(None, |&v| char::from_u32(v as u32)),
            PasswordType::Distinct => DISTINCT_BYTES
                .get(index)
                .map_or(None, |&v| char::from_u32(v as u32)),
            PasswordType::Emoji => EMOJI_CHARS.get(index).copied(),
        }
    }
}

const LEGACY_BYTES: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

const DISTINCT_BYTES: &[u8; 64] =
    b"@#$%&*123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

const EMOJI_CHARS: &[char; 64] = &[
    // U+1F60A, U+1F60D, U+1F61B, U+1F62D, U+1F60E, U+1F47D, U+1F480, U+1F47B,
    '😊', '😍', '😛', '😭', '😎', '👽', '💀', '👻',
    // U+270B, U+1F44C, U+1F449, U+1F44D, U+2764, U+1F48B, U+1F64F, U+1F4AA,
    '✋', '👌', '👉', '👍', '❤', '💋', '🙏', '💪',
    // U+1F435, U+1F436, U+1F434, U+1F437, U+1F414, U+1F438, U+1F40D, U+1F42C,
    '🐵', '🐶', '🐴', '🐷', '🐔', '🐸', '🐍', '🐬',
    // U+1F337, U+1F33B, U+1F331, U+1F334, U+1F335, U+1F340, U+1F344, U+1F352,
    '🌻', '🌷', '🌱', '🌴', '🌵', '🍀', '🍄', '🍒',
    // U+1F354, U+1F35F, U+1F355, U+1F366, U+1F37A, U+1F349, U+1F34C, U+1F34E,
    '🍔', '🍟', '🍕', '🍦', '🍺', '🍉', '🍌', '🍎',
    // U+1F3E0, U+23F0, U+1F512, U+2615, U+1F697, U+1F6B2, U+2708, U+1F680,
    '🏠', '⏰', '💊', '☕', '🚗', '🚲', '✈', '🚀',
    // U+2600, U+1F319, U+2B50, U+26A1, U+2614, U+1F308, U+1F525, U+1F4A7,
    '☀', '🌙', '⭐', '⚡', '☔', '🌈', '🔥', '💧',
    // U+1F384, U+1F381, U+1F388, U+1F389, U+1F514, U+1F3C6, U+1F511, U+1F48A,
    '🎄', '🎁', '🎈', '🎉', '🔔', '🏆', '🔒', '🔑',
];
