//! Safety numbers, the Signal way (CHECKLIST 4.2, 10.10).
//!
//! Signal's `NumericFingerprintGenerator`, fingerprint version 0, exactly as
//! libsignal computes it (`rust/protocol/src/fingerprint.rs`):
//!
//! - per party: `h = SHA-512(0x00 0x00 || key || id || key)`, then 5199 more
//!   rounds of `h = SHA-512(h || key)` - 5200 hashes in all;
//! - the first 30 bytes of `h`, in six 5-byte big-endian chunks, each taken
//!   modulo 100000 and written as five digits: 30 digits per party;
//! - the two parties' 30 digits joined, the smaller string first, so both
//!   sides see the same 60 digits.
//!
//! What we feed it: the **account key** (the Ed25519 key one per UIN that
//! signs every device, `keys::OwnKeys::account_key`) as its raw 32 bytes, and
//! the **UIN in ident form** (`sign::ident`) as the stable identifier. Signal
//! feeds its 33-byte serialised identity key (`0x05` type byte and the
//! Curve25519 key) and the phone number or service id; the hash is the same,
//! only the inputs are ours. The test with Signal's own vector proves the
//! hash, the one with ours pins the inputs.
//!
//! One number per pair of accounts: since every device of an account is
//! signed by the account key, a new device of the contact does not change the
//! number, and a server that adds a device of its own cannot make one that
//! verifies (DESIGN.md section 7).

use ring::digest::{Context, SHA512};

/// Signal's iteration count for the displayed number.
pub const ITERATIONS: u32 = 5200;

/// Signal's fingerprint version, two bytes big-endian.
const FINGERPRINT_VERSION: [u8; 2] = [0, 0];

/// One party's fingerprint: 5200 rounds of SHA-512 over the key and the
/// stable identifier.
fn fingerprint(id: &[u8], key: &[u8]) -> [u8; 64] {
    let mut ctx = Context::new(&SHA512);
    ctx.update(&FINGERPRINT_VERSION);
    ctx.update(key);
    ctx.update(id);
    ctx.update(key);
    let mut buf = [0u8; 64];
    buf.copy_from_slice(ctx.finish().as_ref());
    for _ in 1..ITERATIONS {
        let mut ctx = Context::new(&SHA512);
        ctx.update(&buf);
        ctx.update(key);
        buf.copy_from_slice(ctx.finish().as_ref());
    }
    buf
}

/// One party's 30 digits: six 5-byte chunks, each modulo 100000.
fn encoded(fp: &[u8; 64]) -> String {
    fp[..30]
        .chunks_exact(5)
        .map(|c| c.iter().fold(0u64, |acc, &b| (acc << 8) | b as u64) % 100_000)
        .map(|n| format!("{n:05}"))
        .collect()
}

/// The 60 digits two parties compare, from raw key bytes and stable
/// identifiers. Symmetric: either side as "local" gives the same digits.
pub fn digits(local_id: &[u8], local_key: &[u8], remote_id: &[u8], remote_key: &[u8]) -> String {
    let local = encoded(&fingerprint(local_id, local_key));
    let remote = encoded(&fingerprint(remote_id, remote_key));
    if local < remote {
        local + &remote
    } else {
        remote + &local
    }
}

/// The safety number of two accounts: each one's UIN (in any form; it is
/// normalised) and account key.
pub fn safety_number(
    our_uin: &str,
    our_key: &[u8; 32],
    their_uin: &str,
    their_key: &[u8; 32],
) -> String {
    digits(
        crate::sign::ident(our_uin).as_bytes(),
        our_key,
        crate::sign::ident(their_uin).as_bytes(),
        their_key,
    )
}

/// The 60 digits the way Signal shows them: twelve groups of five, four to a
/// line, lines separated by `sep`.
pub fn grouped(digits: &str, sep: &str) -> String {
    let groups: Vec<&str> = (0..digits.len() / 5)
        .map(|i| &digits[i * 5..i * 5 + 5])
        .collect();
    groups
        .chunks(4)
        .map(|row| row.join(" "))
        .collect::<Vec<_>>()
        .join(sep)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// libsignal's own test vector (`fingerprint_test_v1`, `testVectorsVersion1`
    /// in the Java library): two 33-byte identity keys, two phone numbers,
    /// 5200 iterations. The hash and the digits must be Signal's to the byte.
    #[test]
    fn signals_own_vector_gives_signals_digits() {
        let alice = hex("0506863bc66d02b40d27b8d49ca7c09e9239236f9d7d25d6fcca5ce13c7064d868");
        let bob = hex("05f781b6fb32fed9ba1cf2de978d4d5da28dc34046ae814402b5c0dbd96fda907b");
        let (a_id, b_id) = (b"+14152222222", b"+14153333333");

        // The per-party hashes, as Signal's scannable fingerprint carries them
        // (its first 32 bytes).
        assert_eq!(
            fingerprint(a_id, &alice)[..32],
            hex("1e301a0353dce3dbe7684cb8336e85136cdc0ee96219494ada305d62a7bd61df")[..]
        );
        assert_eq!(
            fingerprint(b_id, &bob)[..32],
            hex("d62cbf73a11592015b6b9f1682ac306fea3aaf3885b84d12bca631e9d4fb3a4d")[..]
        );

        let expected = "300354477692869396892869876765458257569162576843440918079131";
        assert_eq!(digits(a_id, &alice, b_id, &bob), expected);
        assert_eq!(digits(b_id, &bob, a_id, &alice), expected);
    }

    /// Our inputs: the raw 32-byte account key and the UIN in ident form.
    /// Derived independently with Python's hashlib (the same steps as above,
    /// which reproduce Signal's vector): UIN 100001 with the key of 32 bytes
    /// 0x01 gives 328125553520778635644826629899; UIN 100002 with 32 bytes
    /// 0x02 gives 622406012579109111185445620967.
    #[test]
    fn our_inputs_give_the_documented_digits() {
        let (k1, k2) = ([1u8; 32], [2u8; 32]);
        assert_eq!(
            encoded(&fingerprint(b"100001", &k1)),
            "328125553520778635644826629899"
        );
        assert_eq!(
            encoded(&fingerprint(b"100002", &k2)),
            "622406012579109111185445620967"
        );
        let expected = "328125553520778635644826629899622406012579109111185445620967";
        assert_eq!(safety_number("100001", &k1, "100002", &k2), expected);
        // The UIN is normalised, as everywhere else.
        assert_eq!(safety_number(" 100001", &k1, "100 002", &k2), expected);
    }

    #[test]
    fn both_sides_see_the_same_number() {
        use vodozemac::Ed25519SecretKey;
        for _ in 0..4 {
            let a = *Ed25519SecretKey::new().public_key().as_bytes();
            let b = *Ed25519SecretKey::new().public_key().as_bytes();
            let mine = safety_number("100001", &a, "100002", &b);
            let theirs = safety_number("100002", &b, "100001", &a);
            assert_eq!(mine, theirs);
            assert_eq!(mine.len(), 60);
            assert!(mine.bytes().all(|c| c.is_ascii_digit()));
        }
    }

    #[test]
    fn a_different_key_or_uin_gives_a_different_number() {
        let (a, b, c) = ([1u8; 32], [2u8; 32], [3u8; 32]);
        let n = safety_number("100001", &a, "100002", &b);
        assert_ne!(n, safety_number("100001", &a, "100002", &c));
        assert_ne!(n, safety_number("100001", &a, "100003", &b));
    }

    #[test]
    fn digits_are_shown_in_twelve_groups_of_five() {
        let d = "328125553520778635644826629899622406012579109111185445620967";
        assert_eq!(
            grouped(d, " / "),
            "32812 55535 20778 63564 / 48266 29899 62240 60125 / 79109 11118 54456 20967"
        );
    }
}
