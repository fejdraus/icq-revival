//! What vouching for a contact's action needs, whatever the action is: an
//! announcement fresh by its sender's clock, and ids that vouch for nothing
//! once their action ended or was refused (seventh audit of 2026-10).
//!
//! Pure and protocol-free. What an announcement binds (a call's SDP hash, a
//! file proposal's digest, a tZer's document hash) is the business of the
//! code for that action (`callneg.rs`, `filesneg.rs`, `crypto.rs`).

use std::collections::HashMap;
use std::hash::Hash;

/// How old an announcement (`IQC1`, `IQF1`, `IQT1`) may be, by its sender's
/// clock, and still vouch for an action (seventh audit of 2026-10), in
/// seconds. The sender's time is the authenticated `time` of the Olm
/// envelope the announcement came in, which the server cannot change; the
/// envelope check alone lets a message be up to
/// [`crate::keys::TIME_SKEW_PAST`] (14 days) old, for offline messages.
pub const ANNOUNCE_MAX_AGE: u64 = 120;
/// How far an announcement's sender's clock may be ahead of ours.
pub const ANNOUNCE_MAX_AHEAD: u64 = 60;

/// Whether an announcement written at `sent` by its sender's clock is fresh
/// at `now` by ours (both seconds): less than [`ANNOUNCE_MAX_AGE`] old and at
/// most [`ANNOUNCE_MAX_AHEAD`] in the future. A server that holds a genuine
/// announcement back can present it later only within this window.
pub fn announcement_fresh(sent: u64, now: u64) -> bool {
    sent <= now.saturating_add(ANNOUNCE_MAX_AHEAD) && now.saturating_sub(sent) < ANNOUNCE_MAX_AGE
}

/// How long the id of an action that ended, or was not let through, vouches
/// for nothing (seventh audit of 2026-10), in milliseconds: an announcement
/// is fresh for [`ANNOUNCE_MAX_AGE`] at most, so this outlasts every one that
/// could still name it.
pub const BURN_KEEP_MS: u64 = 10 * 60 * 1000;
/// Ids kept burned at most; the oldest goes first.
pub const MAX_BURNED: usize = 256;

/// Ids of actions that ended or were refused, with when (milliseconds):
/// nothing vouches for them again while they are kept - not a late
/// announcement, not a delayed one, not a finished action's.
#[derive(Debug, Clone)]
pub struct BurnedIds<K> {
    at: HashMap<K, u64>,
}

impl<K: Eq + Hash + Copy> Default for BurnedIds<K> {
    fn default() -> Self {
        BurnedIds { at: HashMap::new() }
    }
}

impl<K: Eq + Hash + Copy> BurnedIds<K> {
    /// Whether `id` is burned.
    pub fn contains(&self, id: &K) -> bool {
        self.at.contains_key(id)
    }

    /// Burns `id` at `now`. When [`MAX_BURNED`] are kept already, the one
    /// burned longest ago makes room; burning one already burned only
    /// renews its time.
    pub fn burn(&mut self, id: K, now: u64) {
        if !self.at.contains_key(&id) && self.at.len() >= MAX_BURNED {
            if let Some(old) = self.at.iter().min_by_key(|(_, at)| **at).map(|(k, _)| *k) {
                self.at.remove(&old);
            }
        }
        self.at.insert(id, now);
    }

    /// Forgets the ids burned [`BURN_KEEP_MS`] or longer before `now`.
    pub fn expire(&mut self, now: u64) {
        self.at
            .retain(|_, at| now.saturating_sub(*at) < BURN_KEEP_MS);
    }

    pub fn is_empty(&self) -> bool {
        self.at.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_announcement_is_fresh_for_less_than_the_max_age_and_a_little_ahead() {
        let now = 1_000_000;
        assert!(announcement_fresh(now, now));
        assert!(announcement_fresh(now - (ANNOUNCE_MAX_AGE - 1), now));
        assert!(!announcement_fresh(now - ANNOUNCE_MAX_AGE, now));
        assert!(announcement_fresh(now + ANNOUNCE_MAX_AHEAD, now));
        assert!(!announcement_fresh(now + ANNOUNCE_MAX_AHEAD + 1, now));
        // No wrap at the ends of the clock.
        assert!(!announcement_fresh(0, u64::MAX));
        assert!(announcement_fresh(u64::MAX, u64::MAX));
    }

    #[test]
    fn a_full_set_drops_the_oldest_burn() {
        let mut b = BurnedIds::default();
        for i in 0..MAX_BURNED as u64 {
            // Id 0 is burned last of all, so id 1 is the oldest.
            b.burn(i, if i == 0 { 10_000 } else { i });
        }
        b.burn(9999u64, 20_000);
        assert!(b.contains(&9999));
        assert!(!b.contains(&1), "the oldest burn made room");
        assert!(b.contains(&0) && b.contains(&2));
    }

    #[test]
    fn burning_a_burned_id_drops_nothing() {
        let mut b = BurnedIds::default();
        for i in 0..MAX_BURNED as u64 {
            b.burn(i, i);
        }
        b.burn(5u64, 50_000);
        assert!((0..MAX_BURNED as u64).all(|i| b.contains(&i)));
    }

    #[test]
    fn a_burn_lasts_the_keep_time() {
        let mut b = BurnedIds::default();
        b.burn([7u8; 8], 1000);
        b.expire(1000 + BURN_KEEP_MS - 1);
        assert!(b.contains(&[7u8; 8]));
        b.expire(1000 + BURN_KEEP_MS);
        assert!(!b.contains(&[7u8; 8]));
        assert!(b.is_empty());
    }
}
