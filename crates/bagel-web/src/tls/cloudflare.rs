use std::collections::HashMap;

use data_encoding::{
   BASE64,
   HEXLOWER_PERMISSIVE,
};
use http::HeaderMap;
use ring::digest::{
   SHA256,
   digest,
};

use crate::{
   fingerprint::{
      Capture,
      CaptureError,
   },
   hex_encode,
   tls::reference,
};

pub const ORIGIN_TOKEN_HEADER: &str = "x-bagel-origin-token";

#[derive(Clone, Debug)]
struct ClientHash([u8; 20]);

impl TryFrom<&str> for ClientHash {
   type Error = CaptureError;

   fn try_from(encoded: &str) -> Result<Self, Self::Error> {
      let decoded = BASE64
         .decode(encoded.as_bytes())
         .map_err(|_| CaptureError::Invalid)?;
      let bytes = if decoded.len() == 40 {
         HEXLOWER_PERMISSIVE
            .decode(&decoded)
            .map_err(|_| CaptureError::Invalid)?
      } else {
         decoded
      };
      Ok(Self(bytes.try_into().map_err(|_| CaptureError::Invalid)?))
   }
}

#[derive(Clone, Copy, Debug)]
enum Version {
   Tls10,
   Tls11,
   Tls12,
   Tls13,
}

impl Version {
   const fn as_str(self) -> &'static str {
      match self {
         Self::Tls10 => "10",
         Self::Tls11 => "11",
         Self::Tls12 => "12",
         Self::Tls13 => "13",
      }
   }
}

#[derive(Clone, Copy, Debug)]
enum Protocol {
   Http10,
   Http11,
   Http2,
   Http3,
}

impl Protocol {
   const fn as_str(self) -> &'static str {
      match self {
         Self::Http10 => "HTTP/1.0",
         Self::Http11 => "HTTP/1.1",
         Self::Http2 => "HTTP/2",
         Self::Http3 => "HTTP/3",
      }
   }
}

#[derive(Clone, Debug)]
pub struct CloudflareFingerprint {
   version:      Version,
   cipher:       String,
   protocol:     Protocol,
   ciphers:      Option<ClientHash>,
   extensions:   Option<ClientHash>,
   hello_length: Option<u32>,
}

impl CloudflareFingerprint {
   pub fn capture(
      headers: &HeaderMap,
      name: &str,
      token_sha256: &[u8; 32],
      trusted: bool,
   ) -> Capture<Self> {
      let mut values = headers.get_all(name).iter();
      let Some(value) = values.next() else {
         return Capture::Unavailable;
      };
      if !trusted {
         return Capture::Failed(CaptureError::Untrusted);
      }
      if values.next().is_some() {
         return Capture::Failed(CaptureError::Invalid);
      }
      let mut tokens = headers.get_all(ORIGIN_TOKEN_HEADER).iter();
      let Some(token) = tokens.next() else {
         return Capture::Failed(CaptureError::Untrusted);
      };
      if tokens.next().is_some() || token.as_bytes().len() != 64 {
         return Capture::Failed(CaptureError::Untrusted);
      }
      let received = digest(&SHA256, token.as_bytes());
      if !constant_time_eq::constant_time_eq(received.as_ref(), token_sha256) {
         return Capture::Failed(CaptureError::Untrusted);
      }
      value
         .to_str()
         .map_err(|_| CaptureError::Invalid)
         .and_then(Self::parse)
         .into()
   }

   fn parse(value: &str) -> Result<Self, CaptureError> {
      if value.len() > 1024 {
         return Err(CaptureError::Limited);
      }
      let mut parts = value.split(';');
      let version = match parts.next() {
         Some("TLSv1") => Version::Tls10,
         Some("TLSv1.1") => Version::Tls11,
         Some("TLSv1.2") => Version::Tls12,
         Some("TLSv1.3") => Version::Tls13,
         _ => return Err(CaptureError::Invalid),
      };
      let cipher = parts.next().ok_or(CaptureError::Invalid)?;
      if cipher.is_empty()
         || cipher.len() > 128
         || !cipher
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
      {
         return Err(CaptureError::Invalid);
      }
      let protocol = match parts.next() {
         Some("HTTP/1.0") => Protocol::Http10,
         Some("HTTP/1.1") => Protocol::Http11,
         Some("HTTP/2") => Protocol::Http2,
         Some("HTTP/3") => Protocol::Http3,
         _ => return Err(CaptureError::Invalid),
      };
      let ciphers = parts.next().ok_or(CaptureError::Invalid)?;
      let extensions = parts.next().ok_or(CaptureError::Invalid)?;
      let hello_length = match parts.next() {
         Some("") => None,
         Some(length) => {
            let parsed = length.parse().map_err(|_| CaptureError::Invalid)?;
            if !(1..=65_536).contains(&parsed) {
               return Err(CaptureError::Invalid);
            }
            Some(parsed)
         },
         None => return Err(CaptureError::Invalid),
      };
      if parts.next().is_some() {
         return Err(CaptureError::Invalid);
      }
      Ok(Self {
         version,
         cipher: cipher.to_owned(),
         protocol,
         ciphers: (!ciphers.is_empty())
            .then(|| ClientHash::try_from(ciphers))
            .transpose()?,
         extensions: (!extensions.is_empty())
            .then(|| ClientHash::try_from(extensions))
            .transpose()?,
         hello_length,
      })
   }

   /// Hex of the advertised cipher list hash, the one edge field stable
   /// across a browser's connections apart from its GREASE slot.
   #[must_use]
   pub fn ciphers_hex(&self) -> Option<String> {
      self.ciphers.as_ref().map(|hash| hex_encode(&hash.0))
   }

   /// The stacks the reference table allows for the advertised list.
   #[must_use]
   pub fn families(&self) -> Option<&'static [&'static str]> {
      self
         .ciphers
         .as_ref()
         .and_then(|hash| reference::lookup(&hash.0))
         .map(|known| known.families)
   }

   pub fn policy_fields(&self, fields: &mut HashMap<String, String>) {
      let complete =
         self.ciphers.is_some() && self.extensions.is_some() && self.hello_length.is_some();
      fields.insert(
         "edge_status".to_owned(),
         if complete { "complete" } else { "partial" }.to_owned(),
      );
      for (name, value) in [
         ("edge_tls_version", Some(self.version.as_str().to_owned())),
         ("edge_cipher", Some(self.cipher.clone())),
         ("edge_http", Some(self.protocol.as_str().to_owned())),
         (
            "edge_ciphers_sha1",
            self.ciphers.as_ref().map(|hash| hex_encode(&hash.0)),
         ),
         (
            "edge_extensions_sha1",
            self.extensions.as_ref().map(|hash| hex_encode(&hash.0)),
         ),
         (
            "edge_hello_length",
            self.hello_length.map(|length| length.to_string()),
         ),
      ] {
         if let Some(value) = value {
            fields.insert(name.to_owned(), value);
         }
      }
      if let Some(known) = self
         .ciphers
         .as_ref()
         .and_then(|hash| reference::lookup(&hash.0))
      {
         if let Some(family) = known.family() {
            fields.insert("edge_family".to_owned(), family.to_owned());
         }
         fields.insert("edge_list".to_owned(), known.list.to_owned());
         fields.insert("edge_grease".to_owned(), known.grease.to_string());
      }
   }
}
