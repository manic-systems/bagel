use std::{
   collections::HashMap,
   sync::LazyLock,
};

use ring::digest::{
   SHA1_FOR_LEGACY_USE_ONLY,
   digest,
};

/// A cipher list a known TLS stack advertises, in wire order. Cloudflare
/// hashes the list as sent, so each list yields one plain hash plus one per
/// GREASE value for stacks that prepend one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reference {
   pub family: &'static str,
   pub list:   &'static str,
   pub grease: bool,
}

const GREASE: [u16; 16] = [
   0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
   0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
];

// Lists follow the browser profiles maintained in wreq-util, which tracks
// what BoringSSL, NSS and Apple's stack put on the wire per release.
const LISTS: &[(&str, &str, &[u16])] = &[
   ("chromium", "chromium", &[
      0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0xC013, 0xC014,
      0x009C, 0x009D, 0x002F, 0x0035,
   ]),
   ("chromium", "chromium-tls13", &[0x1301, 0x1302, 0x1303]),
   ("firefox", "firefox", &[
      0x1301, 0x1303, 0x1302, 0xC02B, 0xC02F, 0xCCA9, 0xCCA8, 0xC02C, 0xC030, 0xC013, 0xC014,
      0x009C, 0x009D, 0x002F, 0x0035,
   ]),
   ("firefox", "firefox-legacy", &[
      0x1301, 0x1303, 0x1302, 0xC02B, 0xC02F, 0xCCA9, 0xCCA8, 0xC02C, 0xC030, 0xC00A, 0xC009,
      0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035,
   ]),
   ("firefox", "firefox-tls13", &[0x1301, 0x1303, 0x1302]),
   ("safari", "safari", &[
      0x1302, 0x1303, 0x1301, 0xC02C, 0xC02B, 0xCCA9, 0xC030, 0xC02F, 0xCCA8, 0xC00A, 0xC009,
      0xC014, 0xC013, 0x009D, 0x009C, 0x0035, 0x002F, 0xC008, 0xC012, 0x000A,
   ]),
   ("safari", "safari-legacy", &[
      0x1301, 0x1302, 0x1303, 0xC02C, 0xC02B, 0xCCA9, 0xC030, 0xC02F, 0xCCA8, 0xC00A, 0xC009,
      0xC014, 0xC013, 0x009D, 0x009C, 0x0035, 0x002F, 0xC008, 0xC012, 0x000A,
   ]),
   ("safari", "safari-old", &[
      0x1301, 0x1302, 0x1303, 0xC02C, 0xC02B, 0xCCA9, 0xC030, 0xC02F, 0xCCA8, 0xC024, 0xC023,
      0xC00A, 0xC009, 0xC028, 0xC027, 0xC014, 0xC013, 0x009D, 0x009C, 0x003D, 0x003C, 0x0035,
      0x002F, 0xC008, 0xC012, 0x000A,
   ]),
   ("safari", "safari-tls13", &[0x1302, 0x1303, 0x1301]),
   ("okhttp", "okhttp", &[
      0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0xC013, 0xC014,
      0x009C, 0x009D, 0x002F, 0x0035, 0x000A,
   ]),
];

static TABLE: LazyLock<HashMap<[u8; 20], Reference>> = LazyLock::new(|| {
   let mut table = HashMap::new();
   for &(family, list, ciphers) in LISTS {
      table.insert(sha1(None, ciphers), Reference {
         family,
         list,
         grease: false,
      });
      for grease in GREASE {
         table.insert(sha1(Some(grease), ciphers), Reference {
            family,
            list,
            grease: true,
         });
      }
   }
   table
});

fn sha1(grease: Option<u16>, ciphers: &[u16]) -> [u8; 20] {
   let bytes: Vec<u8> = grease
      .into_iter()
      .chain(ciphers.iter().copied())
      .flat_map(u16::to_be_bytes)
      .collect();
   digest(&SHA1_FOR_LEGACY_USE_ONLY, &bytes)
      .as_ref()
      .try_into()
      .expect("sha1 output is 20 bytes")
}

/// Look up the stack behind a Cloudflare cipher list hash.
#[must_use]
pub fn lookup(ciphers_sha1: &[u8; 20]) -> Option<Reference> {
   TABLE.get(ciphers_sha1).copied()
}
