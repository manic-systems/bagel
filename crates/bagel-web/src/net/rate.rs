use std::{
   collections::HashMap,
   hash::{
      DefaultHasher,
      Hash,
      Hasher as _,
   },
   sync::Mutex,
   time::{
      Duration,
      Instant,
   },
};

use crate::SourceNetwork;

pub const SHARD_COUNT: usize = 64;
pub const DEFAULT_CAPACITY: usize = 65_536;
pub const MIN_CAPACITY: usize = 1_024;
pub const MAX_CAPACITY: usize = 1_048_576;

const WINDOW: usize = 60;

/// Immutable per-request view of the counters over the last one, ten and
/// sixty buckets, taken after the current event has been counted.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RateSnapshot {
   pub last_1:  u32,
   pub last_10: u32,
   pub last_60: u32,
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct RateKey {
   host:    String,
   network: SourceNetwork,
}

#[derive(Clone)]
struct Entry {
   buckets:   [u32; WINDOW],
   last_tick: u64,
   last_used: u64,
}

#[derive(Default)]
struct Shard {
   entries: HashMap<RateKey, Entry>,
   used:    u64,
}

/// Sharded LRU tracker of per-key event counts over sixty buckets of
/// monotonic time. The request tracker uses one-second buckets and only
/// records requests entering ordinary policy evaluation.
pub struct RateTracker {
   shards:         Vec<Mutex<Shard>>,
   shard_capacity: usize,
   capacity:       usize,
   bucket:         Duration,
   epoch:          Instant,
}

impl RateTracker {
   #[must_use]
   pub fn new(capacity: usize) -> Self {
      Self::with_bucket(capacity, Duration::from_secs(1))
   }

   #[must_use]
   pub fn with_bucket(capacity: usize, bucket: Duration) -> Self {
      Self {
         shards: std::iter::repeat_with(|| Mutex::new(Shard::default()))
            .take(SHARD_COUNT)
            .collect(),
         shard_capacity: capacity.div_ceil(SHARD_COUNT).max(1),
         capacity,
         bucket,
         epoch: Instant::now(),
      }
   }

   fn tick(&self) -> u64 {
      self
         .epoch
         .elapsed()
         .as_nanos()
         .checked_div(self.bucket.as_nanos())
         .unwrap_or(0) as u64
   }

   #[must_use]
   pub const fn capacity(&self) -> usize {
      self.capacity
   }

   /// Count the current event and return the counts including it.
   #[must_use]
   pub fn record(&self, host: &str, network: SourceNetwork) -> RateSnapshot {
      self.record_at(host, network, self.tick())
   }

   /// Read the counts for a key without recording anything. Absent keys read
   /// as zero, since nothing happened in the window.
   #[must_use]
   pub fn peek(&self, host: &str, network: SourceNetwork) -> RateSnapshot {
      self.peek_at(host, network, self.tick())
   }

   #[must_use]
   pub fn peek_at(&self, host: &str, network: SourceNetwork, tick: u64) -> RateSnapshot {
      let key = RateKey {
         host: host.to_owned(),
         network,
      };
      let shard = self
         .shards
         .get(Self::shard_index(&key))
         .expect("shard index is bounded by SHARD_COUNT")
         .lock()
         .unwrap_or_else(std::sync::PoisonError::into_inner);
      let Some(entry) = shard.entries.get(&key) else {
         return RateSnapshot {
            last_1:  0,
            last_10: 0,
            last_60: 0,
         };
      };
      let stale = tick.saturating_sub(entry.last_tick);
      let sum = |span: u64| {
         (stale..span.min(tick + 1))
            .map(|offset| entry.buckets[((tick + WINDOW as u64 - offset) % WINDOW as u64) as usize])
            .fold(0_u32, u32::saturating_add)
      };
      RateSnapshot {
         last_1:  if stale == 0 {
            entry.buckets[(tick % WINDOW as u64) as usize]
         } else {
            0
         },
         last_10: sum(10),
         last_60: sum(60),
      }
   }

   fn shard_index(key: &RateKey) -> usize {
      let mut hasher = DefaultHasher::new();
      key.hash(&mut hasher);
      (hasher.finish() as usize) % SHARD_COUNT
   }

   #[must_use]
   pub fn record_at(&self, host: &str, network: SourceNetwork, tick: u64) -> RateSnapshot {
      let key = RateKey {
         host: host.to_owned(),
         network,
      };

      let mut shard = self
         .shards
         .get(Self::shard_index(&key))
         .expect("shard index is bounded by SHARD_COUNT")
         .lock()
         .unwrap_or_else(std::sync::PoisonError::into_inner);
      shard.used += 1;
      let used = shard.used;

      if !shard.entries.contains_key(&key) && shard.entries.len() >= self.shard_capacity {
         Self::evict(&mut shard.entries, tick);
      }

      let entry = shard.entries.entry(key).or_insert_with(|| {
         Entry {
            buckets:   [0; WINDOW],
            last_tick: tick,
            last_used: used,
         }
      });
      entry.last_used = used;

      if tick > entry.last_tick {
         let stale = (tick - entry.last_tick).min(WINDOW as u64);
         for offset in 0..stale {
            entry.buckets[((tick - offset) % WINDOW as u64) as usize] = 0;
         }
         entry.last_tick = tick;
      }

      let current = (tick % WINDOW as u64) as usize;
      entry.buckets[current] = entry.buckets[current].saturating_add(1);

      let sum = |span: u64| {
         (0..span.min(tick + 1))
            .map(|offset| entry.buckets[((tick + WINDOW as u64 - offset) % WINDOW as u64) as usize])
            .fold(0_u32, u32::saturating_add)
      };

      RateSnapshot {
         last_1:  entry.buckets[current],
         last_10: sum(10),
         last_60: sum(60),
      }
   }

   fn evict(entries: &mut HashMap<RateKey, Entry>, tick: u64) {
      entries.retain(|_, entry| entry.last_tick + WINDOW as u64 > tick);
      if let Some(oldest) = entries
         .iter()
         .min_by_key(|(_, entry)| entry.last_used)
         .map(|(key, _)| key.clone())
      {
         entries.remove(&oldest);
      }
   }

   #[must_use]
   pub fn len(&self) -> usize {
      self
         .shards
         .iter()
         .map(|shard| {
            shard
               .lock()
               .unwrap_or_else(std::sync::PoisonError::into_inner)
               .entries
               .len()
         })
         .sum()
   }

   #[must_use]
   pub fn is_empty(&self) -> bool {
      self.len() == 0
   }
}

#[cfg(test)]
mod tests {
   use std::net::{
      IpAddr,
      Ipv4Addr,
   };

   use super::*;

   fn net(last: u8) -> SourceNetwork {
      SourceNetwork::from_ip(IpAddr::V4(Ipv4Addr::new(10, 0, last, 1)))
   }

   #[test]
   fn windows_rotate() {
      let tracker = RateTracker::new(MIN_CAPACITY);
      for tick in 0..30 {
         let _ = tracker.record_at("example.test", net(0), tick);
      }
      let snap = tracker.record_at("example.test", net(0), 30);
      assert_eq!(snap.last_1, 1);
      assert_eq!(snap.last_10, 10);
      assert_eq!(snap.last_60, 31);

      let snap = tracker.record_at("example.test", net(0), 89);
      assert_eq!(snap.last_1, 1);
      assert_eq!(snap.last_10, 1);
      assert_eq!(snap.last_60, 2);

      let snap = tracker.record_at("example.test", net(0), 200);
      assert_eq!(snap.last_60, 1);
   }

   #[test]
   fn capacity_stays_bounded() {
      let tracker = RateTracker::new(MIN_CAPACITY);
      for host_index in 0..(MIN_CAPACITY * 2) {
         let _ = tracker.record_at(&format!("host-{host_index}.test"), net(0), 100);
      }
      assert!(tracker.len() <= MIN_CAPACITY);
   }

   #[test]
   fn distinct_keys_do_not_share_counts() {
      let tracker = RateTracker::new(MIN_CAPACITY);
      for _ in 0..5 {
         let _ = tracker.record_at("example.test", net(0), 100);
      }
      let snap = tracker.record_at("example.test", net(1), 100);
      assert_eq!(snap.last_60, 1);
      let snap = tracker.record_at("other.test", net(0), 100);
      assert_eq!(snap.last_60, 1);
   }
}
