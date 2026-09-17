use std::time::Duration;

use ring::digest::{
   SHA256,
   digest,
};

use crate::{
   hex_encode,
   net::decay_map::DecayMap,
};

const WINDOW: Duration = Duration::from_hours(1);
const BEACON_BUCKET_SECS: u64 = 600;
pub const BEACON_PREFIX: &str = "/__bagel/static/t/";

/// What one clearance session has done with the pages it was served.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VisitSnapshot {
   /// Documents served since the session last rendered one, or ever when it
   /// never has.
   pub documents: u32,
   /// Requests whose `sec-fetch-dest` named a subresource.
   pub assets:    u32,
   /// The session fetched a positive beacon, so a style engine ran.
   pub rendered:  bool,
   /// The session fetched a beacon no browser evaluates, so it grabs URLs.
   pub greedy:    bool,
}

/// Per-session visit records keyed by the 32-byte clearance session.
pub struct VisitTracker {
   records: DecayMap<[u8; 32], VisitSnapshot>,
}

impl Default for VisitTracker {
   fn default() -> Self {
      Self {
         records: DecayMap::new(WINDOW),
      }
   }
}

impl VisitTracker {
   /// Count a request that entered policy evaluation and return the record
   /// including it.
   pub fn record(&self, session: [u8; 32], document: bool) -> VisitSnapshot {
      let mut record = self.records.get(&session).unwrap_or_default();
      if document {
         record.documents = record.documents.saturating_add(1);
      } else {
         record.assets = record.assets.saturating_add(1);
      }
      self.records.set(session, record);
      record
   }

   pub fn record_beacon(&self, session: [u8; 32], kind: BeaconKind) {
      let mut record = self.records.get(&session).unwrap_or_default();
      match kind {
         BeaconKind::Positive => {
            record.rendered = true;
            record.documents = 0;
         },
         BeaconKind::Negative => record.greedy = true,
      }
      self.records.set(session, record);
   }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BeaconKind {
   Positive,
   Negative,
}

impl BeaconKind {
   const fn tag(self) -> &'static [u8] {
      match self {
         Self::Positive => b"render",
         Self::Negative => b"never",
      }
   }
}

fn beacon_id(
   server_key: &[u8],
   session: &[u8; 32],
   host: &str,
   bucket: u64,
   kind: BeaconKind,
) -> String {
   let mut material = Vec::with_capacity(server_key.len() + 32 + host.len() + 8 + 6);
   material.extend_from_slice(server_key);
   material.extend_from_slice(session);
   material.extend_from_slice(host.as_bytes());
   material.extend_from_slice(&bucket.to_be_bytes());
   material.extend_from_slice(kind.tag());
   hex_encode(&digest(&SHA256, &material).as_ref()[..16])
}

const fn current_bucket(now: u64) -> u64 {
   now / BEACON_BUCKET_SECS
}

/// The style block and host element appended to a proxied page.
///
/// The positive image loads only once styles resolve and a box exists, and
/// the negative one sits under a media query no browser evaluates true.
#[must_use]
pub fn beacon_fragment(server_key: &[u8], session: &[u8; 32], host: &str, now: u64) -> String {
   let bucket = current_bucket(now);
   let positive = beacon_id(server_key, session, host, bucket, BeaconKind::Positive);
   let negative = beacon_id(server_key, session, host, bucket, BeaconKind::Negative);
   let class = &positive[..8];
   format!(
      "<style>@media \
       (min-width:1px){{.b{class}::after{{content:\"\";position:absolute;width:1px;height:1px;\
       opacity:0;background:url({BEACON_PREFIX}{positive}.svg)}}}}@media \
       (max-width:0px){{.b{class}::before{{content:\"\";background:url({BEACON_PREFIX}{negative}.\
       svg)}}}}</style><i class=\"b{class}\"></i>"
   )
}

/// Resolve a fetched beacon id back to its kind for this session, accepting
/// the current and previous bucket so a page served near a boundary still
/// counts.
#[must_use]
pub fn classify_beacon(
   server_key: &[u8],
   session: &[u8; 32],
   host: &str,
   now: u64,
   id: &str,
) -> Option<BeaconKind> {
   let bucket = current_bucket(now);
   for candidate in [bucket, bucket.saturating_sub(1)] {
      for kind in [BeaconKind::Positive, BeaconKind::Negative] {
         let expected = beacon_id(server_key, session, host, candidate, kind);
         if constant_time_eq::constant_time_eq(expected.as_bytes(), id.as_bytes()) {
            return Some(kind);
         }
      }
   }
   None
}
