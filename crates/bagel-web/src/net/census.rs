use std::{
   collections::{
      HashMap,
      HashSet,
   },
   time::{
      Duration,
      Instant,
   },
};

use parking_lot::Mutex;

use crate::SourceNetwork;

const GENERATION: Duration = Duration::from_hours(4);
const CLAIM_CAP: usize = 4096;
const NETWORK_CAP: usize = 4096;
const PAIR_CAP: usize = 64;

/// Network counts behind a browser claim and behind its pairing with the
/// current transport fingerprint.
///
/// Counts span the current and previous generation, so a network active in
/// both is counted twice in each figure and the ratio stays like for like.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CensusSnapshot {
   pub claim_networks: u32,
   pub pair_networks:  u32,
}

impl CensusSnapshot {
   /// Networks presenting this pairing per thousand presenting the claim.
   #[must_use]
   pub fn pair_permille(&self) -> u32 {
      if self.claim_networks == 0 {
         return 0;
      }
      u32::try_from(u64::from(self.pair_networks) * 1000 / u64::from(self.claim_networks))
         .unwrap_or(u32::MAX)
   }
}

#[derive(Default)]
struct ClaimEntry {
   networks: HashSet<SourceNetwork>,
   pairs:    HashMap<String, HashSet<SourceNetwork>>,
}

impl ClaimEntry {
   fn pair_len(&self, fingerprint: &str) -> usize {
      self.pairs.get(fingerprint).map_or(0, HashSet::len)
   }
}

struct Generations {
   rotated:  Instant,
   current:  HashMap<String, ClaimEntry>,
   previous: HashMap<String, ClaimEntry>,
}

impl Generations {
   fn rotate(&mut self, now: Instant) {
      let elapsed = now.duration_since(self.rotated);
      if elapsed >= GENERATION * 2 {
         self.previous.clear();
         self.current.clear();
         self.rotated = now;
      } else if elapsed >= GENERATION {
         self.previous = std::mem::take(&mut self.current);
         self.rotated = now;
      }
   }
}

/// Learns which transport fingerprints each browser claim presents.
///
/// Observations are counted per source network in two rotating generations.
/// The daemon trains it from its own traffic, so a claim key with few
/// networks behind it cannot support a verdict and policy has to guard on
/// the claim count.
pub struct FingerprintCensus {
   generations: Mutex<Generations>,
}

impl Default for FingerprintCensus {
   fn default() -> Self {
      Self {
         generations: Mutex::new(Generations {
            rotated:  Instant::now(),
            current:  HashMap::new(),
            previous: HashMap::new(),
         }),
      }
   }
}

impl FingerprintCensus {
   /// Record that `network` presented `claim` with `fingerprint` and return
   /// the counts including it. `None` means the census is saturated for
   /// this claim and cannot vouch either way.
   pub fn observe(
      &self,
      claim: &str,
      fingerprint: &str,
      network: SourceNetwork,
   ) -> Option<CensusSnapshot> {
      let mut generations = self.generations.lock();
      generations.rotate(Instant::now());

      let Generations {
         current, previous, ..
      } = &mut *generations;
      if !current.contains_key(claim) && current.len() >= CLAIM_CAP {
         return None;
      }
      let entry = current.entry(claim.to_owned()).or_default();
      if entry.networks.len() < NETWORK_CAP {
         entry.networks.insert(network);
      }
      if !entry.pairs.contains_key(fingerprint) && entry.pairs.len() >= PAIR_CAP {
         return None;
      }
      let pair = entry.pairs.entry(fingerprint.to_owned()).or_default();
      if pair.len() < NETWORK_CAP {
         pair.insert(network);
      }

      let older = previous.get(claim);
      let claim_networks = entry.networks.len() + older.map_or(0, |old| old.networks.len());
      let pair_networks =
         entry.pair_len(fingerprint) + older.map_or(0, |old| old.pair_len(fingerprint));
      Some(CensusSnapshot {
         claim_networks: u32::try_from(claim_networks).unwrap_or(u32::MAX),
         pair_networks:  u32::try_from(pair_networks).unwrap_or(u32::MAX),
      })
   }
}
