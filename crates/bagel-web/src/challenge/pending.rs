use std::{
   collections::{
      BTreeSet,
      HashMap,
      hash_map::Entry,
   },
   net::IpAddr,
   sync::Arc,
   time::{
      Duration,
      Instant,
   },
};

use parking_lot::Mutex;
use ring::{
   digest::{
      Context,
      SHA256,
   },
   rand::{
      SecureRandom as _,
      SystemRandom,
   },
};
use thiserror::Error;
use tokio::sync::{
   OwnedSemaphorePermit,
   Semaphore,
};

use crate::{
   SourceNetwork,
   challenge::types::ChallengeKey,
   net::rate::RateTracker,
};

const CAPACITY: usize = 65_536;
const LIFETIME: Duration = Duration::from_secs(300);

pub struct ChallengeBinding {
   host:    String,
   network: SourceNetwork,
   digest:  [u8; 32],
}

impl ChallengeBinding {
   #[must_use]
   pub fn new(
      session: &[u8; 32],
      host: &str,
      client_ip: IpAddr,
      challenge: &str,
      user_agent: &[u8],
      revision: u64,
   ) -> Self {
      let mut digest = Context::new(&SHA256);
      for part in [
         session.as_slice(),
         host.as_bytes(),
         client_ip.to_string().as_bytes(),
         challenge.as_bytes(),
         user_agent,
         &revision.to_le_bytes(),
      ] {
         digest.update(&part.len().to_le_bytes());
         digest.update(part);
      }
      Self {
         host:    host.to_owned(),
         network: SourceNetwork::from_ip(client_ip),
         digest:  digest
            .finish()
            .as_ref()
            .try_into()
            .expect("SHA-256 has 32 bytes"),
      }
   }
}

struct PendingChallenge {
   binding:  [u8; 32],
   pass_key: ChallengeKey,
   level:    u32,
   expiry:   Instant,
}

#[derive(Default)]
struct PendingTable {
   challenges: HashMap<ChallengeKey, PendingChallenge>,
   expiries:   BTreeSet<(Instant, ChallengeKey)>,
}

impl PendingTable {
   fn expire(&mut self, now: Instant) {
      while let Some(&(expiry, key)) = self.expiries.first() {
         if expiry > now {
            break;
         }
         self.expiries.pop_first();
         self.challenges.remove(&key);
      }
   }
}

#[derive(Debug, Error)]
pub enum IssueError {
   #[error("challenge issuance rate exceeded")]
   Limited,
   #[error("pending challenge capacity exhausted")]
   Full,
   #[error("challenge randomness unavailable")]
   Random,
}

pub struct PendingChallenges {
   pending:      Mutex<PendingTable>,
   issuance:     RateTracker,
   verification: RateTracker,
   slots:        Arc<Semaphore>,
}

impl Default for PendingChallenges {
   fn default() -> Self {
      Self {
         pending:      Mutex::new(PendingTable::default()),
         issuance:     RateTracker::new(CAPACITY),
         verification: RateTracker::new(CAPACITY),
         slots:        Arc::new(Semaphore::new(8)),
      }
   }
}

impl PendingChallenges {
   pub fn issue(
      &self,
      binding: &ChallengeBinding,
      pass_key: ChallengeKey,
      level: u32,
      duration: Duration,
   ) -> Result<ChallengeKey, IssueError> {
      let rate = self.issuance.record(&binding.host, binding.network);
      if rate.last_1s > 32 || rate.last_60s > 120 {
         return Err(IssueError::Limited);
      }

      let now = Instant::now();
      let mut pending = self.pending.lock();
      pending.expire(now);
      if pending.challenges.len() >= CAPACITY {
         return Err(IssueError::Full);
      }

      let mut key = [0; 32];
      loop {
         SystemRandom::new()
            .fill(&mut key)
            .map_err(|_| IssueError::Random)?;
         if !pending.challenges.contains_key(&key) {
            break;
         }
      }
      let expiry = now + duration.min(LIFETIME);
      pending.challenges.insert(key, PendingChallenge {
         binding: binding.digest,
         pass_key,
         level,
         expiry,
      });
      pending.expiries.insert((expiry, key));
      Ok(key)
   }

   #[must_use]
   pub fn admit_verification(&self, host: &str, client_ip: IpAddr) -> bool {
      let rate = self
         .verification
         .record(host, SourceNetwork::from_ip(client_ip));
      rate.last_1s <= 32 && rate.last_60s <= 120
   }

   #[must_use]
   pub fn verification_slot(&self) -> Option<OwnedSemaphorePermit> {
      Arc::clone(&self.slots).try_acquire_owned().ok()
   }

   #[must_use]
   pub fn redeem(
      &self,
      key: &ChallengeKey,
      binding: &ChallengeBinding,
      level: u32,
   ) -> Option<ChallengeKey> {
      let mut pending = self.pending.lock();
      pending.expire(Instant::now());
      let Entry::Occupied(entry) = pending.challenges.entry(*key) else {
         return None;
      };
      if entry.get().binding != binding.digest || entry.get().level != level {
         return None;
      }

      let redeemed = entry.remove();
      pending.expiries.remove(&(redeemed.expiry, *key));
      Some(redeemed.pass_key)
   }
}
