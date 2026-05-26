//! CAK Cache per IEEE 802.1X-2020, Clause 12.6.
//!
//! Implements: #37 (REQ-F-LOGON-005: CAK Cache Management)
//!
//! IMPORTANT: This implementation is based on understanding of IEEE 802.1X-2020.
//! No copyrighted content from the standard is reproduced.

use std::collections::HashMap;
use std::time::Duration;

use pae::{Cak, Ckn, CipherSuite};

use crate::LogonError;

/// CAK cache entry — a cached CAK+CKN pair with metadata.
///
/// Per IEEE 802.1X-2020, Clause 12.6.
#[derive(Debug)]
pub struct CakCacheEntry {
    /// Cached CAK.
    cak: Cak,
    /// CKN that identifies this CAK.
    ckn: Ckn,
    /// Cipher suite for this CA.
    cipher_suite: CipherSuite,
    /// Creation time.
    created_at: Duration,
    /// Expiry time (CAK lifetime).
    expires_at: Duration,
}

impl CakCacheEntry {
    /// Create a new cache entry. Per Cl.12.6.
    ///
    /// Implements: #37 (REQ-F-LOGON-005)
    pub fn new(
        cak: Cak,
        ckn: Ckn,
        cipher_suite: CipherSuite,
        created_at: Duration,
        lifetime: Duration,
    ) -> Self {
        Self {
            cak,
            ckn,
            cipher_suite,
            created_at,
            expires_at: created_at + lifetime,
        }
    }

    /// Whether this entry has expired.
    pub fn is_expired(&self, now: Duration) -> bool {
        now >= self.expires_at
    }

    /// The CKN for this cache entry.
    pub fn ckn(&self) -> &Ckn {
        &self.ckn
    }

    /// The CAK for this cache entry.
    pub fn cak(&self) -> &Cak {
        &self.cak
    }

    /// The cipher suite for this cache entry.
    pub fn cipher_suite(&self) -> CipherSuite {
        self.cipher_suite
    }

    /// Creation time.
    pub fn created_at(&self) -> Duration {
        self.created_at
    }

    /// Expiry time.
    pub fn expires_at(&self) -> Duration {
        self.expires_at
    }
}

/// CAK cache — stores pre-shared or previously derived CAKs.
///
/// Per IEEE 802.1X-2020, Clause 12.6.
/// Mutable entity: entries are inserted, looked up, and expired.
pub struct CakCache {
    /// Cached entries indexed by CKN.
    entries: HashMap<Ckn, CakCacheEntry>,
}

impl CakCache {
    /// Create an empty CAK cache.
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Look up a CAK by CKN. Per Cl.12.6.
    ///
    /// Returns `None` if not found or expired (expired entries are removed).
    ///
    /// Implements: #37 (REQ-F-LOGON-005)
    pub fn lookup(&mut self, ckn: &Ckn, now: Duration) -> Option<&CakCacheEntry> {
        let expired = self.entries.get(ckn).is_some_and(|e| e.is_expired(now));
        if expired {
            self.entries.remove(ckn);
            return None;
        }
        self.entries.get(ckn)
    }

    /// Take (remove and return) a CAK by CKN. Per Cl.12.6.
    ///
    /// Returns `None` if not found or expired.
    /// The returned entry is owned, suitable for passing to MKA participant creation.
    pub fn take(&mut self, ckn: &Ckn, now: Duration) -> Result<CakCacheEntry, LogonError> {
        match self.entries.remove(ckn) {
            Some(entry) => {
                if entry.is_expired(now) {
                    Err(LogonError::CakCacheExpired)
                } else {
                    Ok(entry)
                }
            }
            None => Err(LogonError::CakCacheMiss),
        }
    }

    /// Insert a CAK into the cache. Per Cl.12.6.
    pub fn insert(&mut self, entry: CakCacheEntry) {
        let ckn = entry.ckn().clone();
        self.entries.insert(ckn, entry);
    }

    /// Remove expired entries. Per Cl.12.6.
    ///
    /// Returns the number of entries removed.
    pub fn expire(&mut self, now: Duration) -> usize {
        let expired: Vec<Ckn> = self
            .entries
            .iter()
            .filter(|(_, v)| v.is_expired(now))
            .map(|(k, _)| k.clone())
            .collect();
        let count = expired.len();
        for ckn in expired {
            self.entries.remove(&ckn);
        }
        count
    }

    /// Number of cached entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for CakCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cak() -> Cak {
        Cak::from_bytes(&[0x0A; 16]).unwrap()
    }

    fn make_ckn() -> Ckn {
        Ckn::from_bytes(vec![0x0B; 16]).unwrap()
    }

    /// Verifies: #37 (REQ-F-LOGON-005)
    /// AC1: CAK stored with CKN, cipher suite, and expiration lifetime.
    #[test]
    fn test_cache_insert_and_lookup() {
        let mut cache = CakCache::new();
        let cak = make_cak();
        let ckn = make_ckn();
        let now = Duration::from_secs(100);

        let entry = CakCacheEntry::new(
            cak,
            ckn.clone(),
            CipherSuite::GcmAes128,
            now,
            Duration::from_secs(3600),
        );
        cache.insert(entry);

        let found = cache.lookup(&ckn, now).unwrap();
        assert_eq!(found.cipher_suite(), CipherSuite::GcmAes128);
        assert_eq!(cache.len(), 1);
    }

    /// Verifies: #37 (REQ-F-LOGON-005)
    /// AC2: Cached CAK deleted when lifetime expires.
    #[test]
    fn test_cache_entry_expired() {
        let mut cache = CakCache::new();
        let cak = make_cak();
        let ckn = make_ckn();
        let now = Duration::from_secs(100);

        let entry = CakCacheEntry::new(
            cak,
            ckn.clone(),
            CipherSuite::GcmAes128,
            now,
            Duration::from_secs(60),
        );
        cache.insert(entry);

        // Not expired yet
        assert!(cache.lookup(&ckn, Duration::from_secs(150)).is_some());

        // Expired
        assert!(cache.lookup(&ckn, Duration::from_secs(200)).is_none());
        assert!(cache.is_empty());
    }

    /// Verifies: #37 (REQ-F-LOGON-005)
    /// Cache miss returns None.
    #[test]
    fn test_cache_miss() {
        let mut cache = CakCache::new();
        let ckn = make_ckn();
        assert!(cache.lookup(&ckn, Duration::ZERO).is_none());
    }

    /// Verifies: #37 (REQ-F-LOGON-005)
    /// expire() removes all expired entries.
    #[test]
    fn test_cache_expire_removes_expired() {
        let mut cache = CakCache::new();
        let now = Duration::from_secs(100);

        let ckn1 = Ckn::from_bytes(vec![0x01; 16]).unwrap();
        let ckn2 = Ckn::from_bytes(vec![0x02; 16]).unwrap();

        cache.insert(CakCacheEntry::new(
            make_cak(),
            ckn1,
            CipherSuite::GcmAes128,
            now,
            Duration::from_secs(60),
        ));
        cache.insert(CakCacheEntry::new(
            make_cak(),
            ckn2,
            CipherSuite::GcmAes128,
            now,
            Duration::from_secs(3600),
        ));

        assert_eq!(cache.len(), 2);
        let removed = cache.expire(Duration::from_secs(200));
        assert_eq!(removed, 1);
        assert_eq!(cache.len(), 1);
    }

    /// Verifies: #37 (REQ-F-LOGON-005)
    /// AC3: Cached CAK taken for MKA participant creation.
    #[test]
    fn test_cache_take() {
        let mut cache = CakCache::new();
        let cak = make_cak();
        let ckn = make_ckn();
        let now = Duration::from_secs(100);

        cache.insert(CakCacheEntry::new(
            cak,
            ckn.clone(),
            CipherSuite::GcmAes128,
            now,
            Duration::from_secs(3600),
        ));

        let entry = cache.take(&ckn, now).unwrap();
        assert_eq!(entry.cipher_suite(), CipherSuite::GcmAes128);
        assert!(cache.is_empty()); // taken out
    }

    /// Verifies: #37 (REQ-F-LOGON-005)
    /// Take on expired entry returns error.
    #[test]
    fn test_cache_take_expired() {
        let mut cache = CakCache::new();
        let cak = make_cak();
        let ckn = make_ckn();
        let now = Duration::from_secs(100);

        cache.insert(CakCacheEntry::new(
            cak,
            ckn.clone(),
            CipherSuite::GcmAes128,
            now,
            Duration::from_secs(60),
        ));

        let result = cache.take(&ckn, Duration::from_secs(200));
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), LogonError::CakCacheExpired));
    }

    /// Verifies: #37 (REQ-F-LOGON-005)
    /// Take on missing entry returns CakCacheMiss.
    #[test]
    fn test_cache_take_miss() {
        let mut cache = CakCache::new();
        let ckn = make_ckn();
        let result = cache.take(&ckn, Duration::ZERO);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), LogonError::CakCacheMiss));
    }
}
