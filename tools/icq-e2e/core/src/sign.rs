//! The byte strings the key directory's signatures cover
//! (docs/e2e/KEY-DIRECTORY-API.md section 5).
//!
//! A message is the 12 ASCII bytes `OSCAR-E2E-v1` and then fields, each a
//! 16-bit big-endian length and the field's bytes: the purpose, the account's
//! screen name in ident form, and the fields of that purpose. The server builds
//! the same strings in `server/e2e/sign.go`; the vectors of section 5.1 pin both.

/// What every signed message starts with.
pub const PREFIX: &[u8] = b"OSCAR-E2E-v1";

fn message(purpose: &str, screen_name: &str, fields: &[&[u8]]) -> Vec<u8> {
    let mut out = PREFIX.to_vec();
    let sn = ident(screen_name);
    for f in [purpose.as_bytes(), sn.as_bytes()].iter().chain(fields) {
        out.extend_from_slice(&(f.len() as u16).to_be_bytes());
        out.extend_from_slice(f);
    }
    out
}

/// A screen name in ident form: lower case, no spaces (`"123456"` for a UIN).
pub fn ident(screen_name: &str) -> String {
    screen_name
        .chars()
        .filter(|c| *c != ' ')
        .flat_map(char::to_lowercase)
        .collect()
}

/// `account`: the account key, signed by itself.
pub fn account(screen_name: &str, account_key: &[u8; 32]) -> Vec<u8> {
    message("account", screen_name, &[account_key])
}

/// `device`: a device's id and keys, signed by the account key.
pub fn device(
    screen_name: &str,
    device_id: u32,
    curve25519: &[u8; 32],
    ed25519: &[u8; 32],
) -> Vec<u8> {
    message(
        "device",
        screen_name,
        &[&device_id.to_be_bytes(), curve25519, ed25519],
    )
}

/// `one-time-key`: a one-time key, signed by the device's Ed25519 key.
pub fn one_time_key(screen_name: &str, device_id: u32, key_id: &str, key: &[u8; 32]) -> Vec<u8> {
    message(
        "one-time-key",
        screen_name,
        &[&device_id.to_be_bytes(), key_id.as_bytes(), key],
    )
}

/// `fallback-key`: a fallback key, signed by the device's Ed25519 key.
pub fn fallback_key(screen_name: &str, device_id: u32, key_id: &str, key: &[u8; 32]) -> Vec<u8> {
    message(
        "fallback-key",
        screen_name,
        &[&device_id.to_be_bytes(), key_id.as_bytes(), key],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use vodozemac::{Ed25519PublicKey, Ed25519SecretKey, Ed25519Signature};

    fn key(seed: u8) -> Ed25519SecretKey {
        Ed25519SecretKey::from_slice(&[seed; 32])
    }

    // The worked example of KEY-DIRECTORY-API.md 5.1.
    #[test]
    fn vectors_of_the_api_document() {
        let account_key = key(0x01);
        let device_key = key(0x02);
        let pk = account_key.public_key();
        assert_eq!(
            pk.to_base64(),
            "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w"
        );
        assert_eq!(
            device_key.public_key().to_base64(),
            "gTl3Dqh9F19Wo1Rmw0x+zMuNipG07jeiXfYPW4/Js5Q"
        );

        let msg = account("123456", pk.as_bytes());
        assert_eq!(
            hex(&msg),
            "4f534341522d4532452d763100076163636f756e7400063132333435360020\
             8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c"
        );
        assert_eq!(
            account_key.sign(&msg).to_base64(),
            "MjyAKwrPALzHWNRPYbORmZJQvdklIhAXH1f5Qw/2OnpggRwVpH5UhcmYT8CdRbUcqSHDx2TcUUxQkohkehUsBw"
        );

        let dev = device("123456", 1, &[0x03; 32], device_key.public_key().as_bytes());
        assert_eq!(
            account_key.sign(&dev).to_base64(),
            "s966Fw1ZvqlxQGnM8pYG5uuRAMBSEw+gjdTQCHQWrQTu9zzNsE1bnOhPdE5kVSmY75GcA8S6fP/e5/Z1J8PjAQ"
        );

        let otk = one_time_key("123456", 1, "AAAAAQ", &[0x04; 32]);
        assert_eq!(
            device_key.sign(&otk).to_base64(),
            "t515M1k9PBHb/f/3K3y6Y5a+gak+BC/9Hz/9OCGPrqQZSRBOl7iKNN+0tg/kpya+rzQ0acn4rcudSzFABiHcBw"
        );

        let fbk = fallback_key("123456", 1, "AAAAAg", &[0x04; 32]);
        assert_eq!(
            device_key.sign(&fbk).to_base64(),
            "6yfz+5itolxEadiy8fM3owUtMLtWYVdFh0RnlTIoraly+Q7PFG7vuVmJUeSbPmdmh0+Ni8E7O9/G94hir3fdDg"
        );

        let sig = Ed25519Signature::from_base64(
            "s966Fw1ZvqlxQGnM8pYG5uuRAMBSEw+gjdTQCHQWrQTu9zzNsE1bnOhPdE5kVSmY75GcA8S6fP/e5/Z1J8PjAQ",
        )
        .unwrap();
        let pk =
            Ed25519PublicKey::from_base64("iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w").unwrap();
        assert!(pk.verify(&dev, &sig).is_ok());
    }

    #[test]
    fn screen_names_in_ident_form() {
        assert_eq!(ident("Some Name"), "somename");
        assert_eq!(
            account("Some Name", &[0; 32]),
            account("somename", &[0; 32])
        );
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}
