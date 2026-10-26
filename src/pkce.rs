//! PKCE (RFC 7636, S256) and the random values a sign-in needs.
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};

/// 32 random bytes as base64url without padding: a PKCE verifier, an OAuth
/// state or a nonce, as pi makes them.
pub fn random_value() -> String {
    URL_SAFE_NO_PAD.encode(random::<32>())
}

/// The S256 challenge for `verifier`: base64url(SHA-256(verifier)).
pub fn challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// A random (version 4) UUID in lowercase.
pub fn uuid() -> String {
    let mut b = random::<16>();
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let hex: String = b.iter().map(|byte| format!("{byte:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}

fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0; N];
    getrandom::fill(&mut bytes).expect("the operating system's random source");
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_is_rfc_7636_appendix_b() {
        assert_eq!(
            challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn values_are_43_url_safe_characters_and_uuids_are_version_4() {
        let value = random_value();
        assert_eq!(value.len(), 43);
        assert!(
            value
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
        assert_ne!(value, random_value());
        let id = uuid();
        let groups: Vec<usize> = id.split('-').map(str::len).collect();
        assert_eq!(groups, [8, 4, 4, 4, 12]);
        assert_eq!(&id[14..15], "4");
        assert!("89ab".contains(&id[19..20]));
    }
}
