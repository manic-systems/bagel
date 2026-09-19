use std::{
   error::Error,
   io,
   num::NonZeroUsize,
   sync::Arc,
   time::Duration,
};

use bagel_solver::host::{
   compression,
   config as solver_config,
};
use bytes::Bytes;
use http::{
   HeaderMap,
   Method,
   StatusCode,
   header,
};
use metrics::counter;
use ring::rand::{
   SecureRandom as _,
   SystemRandom,
};
use vela::{
   delivery::{
      artifact::{
         CACHE_CONTROL,
         CONTENT_TYPE,
         Encoding,
         VARY,
         VariantId,
      },
      pool::{
         DeliveryError,
         Limits,
         Pool,
      },
   },
   prepare::Prepared,
};

use crate::{
   body::{
      Body,
      Request,
      Response,
   },
   challenge::pending::LIFETIME,
   routes::ASSET_VERSION,
};

pub const STATIC_URL: &str = "/__bagel/static/solver.wasm";
pub const STATIC_WASM: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/solver.wasm"));
const STATIC_BROTLI: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/solver.wasm.br"));
const INPUT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/solver.input.wasm"));

pub async fn start() -> Option<Arc<Pool>> {
   let result =
      tokio::task::spawn_blocking(|| -> Result<Arc<Pool>, Box<dyn Error + Send + Sync>> {
         let mut seed = [0; 8];
         SystemRandom::new()
            .fill(&mut seed)
            .map_err(|_| io::Error::other("solver seed randomness unavailable"))?;

         let prepared = Prepared::new(INPUT.to_vec(), solver_config(0))?;

         let pool = Pool::spawn(
            prepared,
            compression(),
            Limits {
               ready:    NonZeroUsize::new(64).expect("ready capacity is positive"),
               issued:   NonZeroUsize::new(4096).expect("retention capacity is positive"),
               lifetime: LIFETIME,
            },
            u64::from_le_bytes(seed),
         )?;

         if let Err(error) = pool.wait_ready(Duration::from_secs(5)) {
            tracing::warn!(?error, "solver variant prefill incomplete");
         }

         Ok(Arc::new(pool))
      })
      .await;

   match result {
      Ok(Ok(pool)) => Some(pool),
      Ok(Err(error)) => {
         tracing::warn!(
            ?error,
            "solver variants unavailable, using the static solver"
         );
         None
      },
      Err(error) => {
         tracing::warn!(%error, "solver startup task failed, using the static solver");
         None
      },
   }
}

#[must_use]
pub fn issue(pool: Option<&Pool>) -> String {
   let reason = if let Some(pool) = pool {
      match pool.issue() {
         Ok(variant) => {
            counter!("bagel_solver_issued_total", "source" => "variant").increment(1);
            return format!("{STATIC_URL}?variant={}", variant.id());
         },
         Err(DeliveryError::Empty) => "empty",
         Err(DeliveryError::Full) => "full",
         Err(_) => "unavailable",
      }
   } else {
      "unavailable"
   };

   counter!("bagel_solver_issued_total", "source" => reason).increment(1);
   format!("{STATIC_URL}?v={}", *ASSET_VERSION)
}

#[must_use]
pub fn serve(pool: Option<&Pool>, variant: Option<&str>, request: &Request) -> Response {
   let encoding = if accepts_brotli(request.headers()) {
      Encoding::Brotli
   } else {
      Encoding::Identity
   };
   let variant = variant
      .and_then(|value| value.parse::<VariantId>().ok())
      .and_then(|id| pool?.get(id).ok().flatten());

   let (content, source, cache_control) = variant.as_ref().map_or_else(
      || {
         let bytes = if encoding == Encoding::Brotli {
            STATIC_BROTLI
         } else {
            STATIC_WASM
         };
         (bytes, "static", "public, max-age=31536000, immutable")
      },
      |value| (value.bytes(encoding), "variant", CACHE_CONTROL),
   );

   counter!("bagel_solver_served_total", "source" => source).increment(1);

   let mut response = Response::builder()
      .status(StatusCode::OK)
      .header(header::CACHE_CONTROL, cache_control)
      .header(header::VARY, VARY)
      .header(header::CONTENT_TYPE, CONTENT_TYPE)
      .header(header::CONTENT_LENGTH, content.len());

   if let Some(value) = encoding.content_encoding() {
      response = response.header(header::CONTENT_ENCODING, value);
   }

   let body = if request.method() == Method::HEAD {
      Body::empty()
   } else {
      Body::from(Bytes::copy_from_slice(content))
   };

   response
      .body(body)
      .expect("solver response parts are valid")
}

fn accepts_brotli(headers: &HeaderMap) -> bool {
   headers
      .get_all(header::ACCEPT_ENCODING)
      .iter()
      .filter_map(|value| value.to_str().ok())
      .flat_map(|value| value.split(','))
      .map(|item| item.split_once(';').unwrap_or((item, "")))
      .any(|(coding, weight)| {
         coding.trim().eq_ignore_ascii_case("br") && !weight.trim().eq_ignore_ascii_case("q=0")
      })
}

#[cfg(test)]
mod tests {
   use std::{
      error::Error,
      io,
      time::Duration,
   };

   use bagel_solver::host::{
      config,
      validate,
   };
   use vela::worker::{
      Limits,
      Verifier,
   };

   use super::{
      INPUT,
      STATIC_WASM,
   };

   fn rewrite(
      verifier: &Verifier,
      input: &[u8],
      config: &vela::config::Config,
   ) -> Result<(), Box<dyn Error>> {
      let (output, _report) = vela::transform(input, config)?;
      validate(verifier, input, &output)
   }

   #[test]
   fn solver_rewrites_match_native() -> Result<(), Box<dyn Error>> {
      let verifier = Verifier::new(env!("BAGEL_VERIFY_WORKER").as_ref(), Limits {
         timeout: Duration::from_secs(120),
         ..Limits::default()
      })?;
      if INPUT.is_empty() || STATIC_WASM.is_empty() {
         return Err(io::Error::other("solver fixtures are missing or empty").into());
      }
      validate(&verifier, INPUT, STATIC_WASM)?;
      for seed in [0, 1, 42, u64::MAX] {
         rewrite(&verifier, INPUT, &config(seed))?;
      }
      Ok(())
   }
}
