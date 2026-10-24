use std::{
   collections::HashSet,
   ffi::OsStr,
   os::unix::ffi::OsStrExt as _,
   path::{
      Path,
      PathBuf,
   },
   sync::Arc,
};

use bagel_config::web::bind::TlsConfig;
use http::{
   HeaderName,
   HeaderValue,
   Uri,
   uri::{
      Authority,
      Scheme,
   },
};
use rustls::ServerConfig;

use crate::{
   config::{
      BackendConfig,
      CustomTheme,
   },
   error::Error,
   hex_decode,
   hex_encode,
   host::CanonicalHost,
   tls::build_server_config,
};

pub const UNIX_SCHEME: &str = "unix";

#[derive(Clone)]
pub enum Upstream {
   Tcp(Authority),
   Unix(PathBuf),
}

/// A resolved backend: the config plus its upstream.
#[derive(Clone)]
pub struct Backend {
   pub config:       BackendConfig,
   pub upstream:     Upstream,
   pub origin:       Uri,
   pub tls:          Option<Arc<ServerConfig>>,
   pub host:         Option<HeaderValue>,
   pub ip_header:    Option<HeaderName>,
   pub custom_theme: CustomTheme,
}

#[must_use]
pub fn unix_socket_path(uri: &Uri) -> Option<PathBuf> {
   if uri.scheme_str() != Some(UNIX_SCHEME) {
      return None;
   }
   let bytes = hex_decode(uri.host()?)?;
   Some(PathBuf::from(OsStr::from_bytes(&bytes)))
}

impl Upstream {
   fn parse(cfg: &BackendConfig) -> Result<Self, Error> {
      let url = cfg.url.as_ref();
      if let Some(path) = url.strip_prefix("unix:") {
         if !Path::new(path).is_absolute() || path.starts_with("//") {
            return Err(Error::Config(format!(
               "backend '{}' needs an absolute Unix socket path, got {path}",
               cfg.name,
            )));
         }
         return Ok(Self::Unix(PathBuf::from(path)));
      }

      let target: Uri = url
         .parse()
         .map_err(|err| Error::Config(format!("invalid backend URL {url}: {err}")))?;

      if target.scheme() != Some(&Scheme::HTTP) || target.host().is_none() {
         return Err(Error::Config(format!(
            "backend '{}' requires an absolute HTTP or unix: URL, upstream TLS is not implemented",
            cfg.name,
         )));
      }
      if target.path() != "/" || target.query().is_some() {
         return Err(Error::Config(format!(
            "backend '{}' URL cannot contain a path prefix or query",
            cfg.name,
         )));
      }

      let authority = target
         .authority()
         .expect("an absolute HTTP URL has an authority")
         .clone();
      Ok(Self::Tcp(authority))
   }

   /// A Unix socket gets its path hex-encoded as the authority, so each
   /// socket keeps its own connection pool.
   fn origin(&self) -> Result<Uri, http::Error> {
      match self {
         Self::Tcp(authority) => {
            Uri::builder()
               .scheme(Scheme::HTTP)
               .authority(authority.clone())
               .path_and_query("/")
               .build()
         },
         Self::Unix(path) => {
            Uri::builder()
               .scheme(UNIX_SCHEME)
               .authority(hex_encode(path.as_os_str().as_bytes()))
               .path_and_query("/")
               .build()
         },
      }
   }
}

/// A wildcard certificate covers exactly one label, so one probe name below
/// the suffix proves the certificate matches the pattern.
fn certificate_name(pattern: &str) -> Option<String> {
   match pattern {
      "*" => None,
      name => {
         Some(
            name
               .strip_prefix("*.")
               .map_or_else(|| name.to_owned(), |suffix| format!("wildcard.{suffix}")),
         )
      },
   }
}

/// Pool of backends keyed by host pattern.
/// Lookup order: exact match -> wildcard (*.domain) -> fallback ("*").
#[derive(Clone)]
pub struct BackendPool {
   exact:    Vec<(String, Arc<Backend>)>,
   /// Wildcard patterns like `*.example.com` stored as `.example.com` suffix.
   wildcard: Vec<(String, Arc<Backend>)>,
   fallback: Option<Arc<Backend>>,
}

impl BackendPool {
   pub fn build(
      configs: &[BackendConfig],
      default_theme: &CustomTheme,
      listener_tls: &TlsConfig,
   ) -> Result<Self, Error> {
      let mut exact = Vec::new();
      let mut wildcard = Vec::new();
      let mut fallback = None;
      let mut seen = HashSet::new();

      for cfg in configs {
         let upstream = Upstream::parse(cfg)?;
         let origin = upstream.origin().map_err(|err| {
            Error::Config(format!("backend '{}' has an invalid URL, {err}", cfg.name))
         })?;

         let tls = match (&cfg.tls, listener_tls) {
            (Some(_), TlsConfig::None) => {
               return Err(Error::Config(format!(
                  "backend '{}' has a certificate but the listener does not terminate TLS",
                  cfg.name,
               )));
            },
            (None, TlsConfig::Backend) => {
               return Err(Error::Config(format!(
                  "backend '{}' needs a certificate because the listener uses tls \"backend\"",
                  cfg.name,
               )));
            },
            (Some(_), TlsConfig::Manual { .. } | TlsConfig::Acme { .. }) if cfg.name == "*" => {
               return Err(Error::Config(
                  "backend '*' cannot have a certificate when the listener has its own, which \
                   already covers unmatched names"
                     .to_owned(),
               ));
            },
            (Some(cert), _) => {
               let name = certificate_name(&cfg.name);
               let config = build_server_config(&cert.cert_path, &cert.key_path, name.as_deref())
                  .map_err(|err| {
                  Error::Config(format!(
                     "backend '{}' certificate {}, {err}",
                     cfg.name,
                     cert.cert_path.display(),
                  ))
               })?;
               Some(config)
            },
            (None, _) => None,
         };

         let host = cfg
            .host
            .as_deref()
            .map(HeaderValue::from_str)
            .transpose()
            .map_err(|error| {
               Error::Config(format!(
                  "backend '{}' has an invalid host header, {error}",
                  cfg.name
               ))
            })?;
         let ip_header = cfg
            .ip_header
            .as_deref()
            .map(|name| HeaderName::from_bytes(name.as_bytes()))
            .transpose()
            .map_err(|error| {
               Error::Config(format!(
                  "backend '{}' has an invalid ip-header name, {error}",
                  cfg.name
               ))
            })?;

         let mut custom_theme = default_theme.clone();

         if let Some(theme) = &cfg.challenge_template {
            custom_theme.vars.extend(theme.vars.iter().cloned());
            custom_theme
               .light
               .retain(|var| !theme.vars.iter().any(|entry| entry.name == var.name));
            custom_theme
               .dark
               .retain(|var| !theme.vars.iter().any(|entry| entry.name == var.name));
            custom_theme.light.extend(theme.light.iter().cloned());
            custom_theme.dark.extend(theme.dark.iter().cloned());
         }

         let backend = Arc::new(Backend {
            config: cfg.clone(),
            upstream,
            origin,
            tls,
            host,
            ip_header,
            custom_theme,
         });

         // Patterns are canonicalized here so they match the CanonicalHost
         // string built at request entry.
         match cfg.name.as_str() {
            "*" => {
               if !seen.insert("*".to_owned()) {
                  return Err(Error::Config("duplicate backend pattern '*'".to_owned()));
               }
               fallback = Some(backend);
            },
            name if name.starts_with("*.") => {
               let canonical = CanonicalHost::parse(&name[2..])
                  .map_err(|err| Error::Config(format!("backend pattern '{name}': {err}")))?;
               let pattern = format!(".{canonical}");
               if !seen.insert(pattern.clone()) {
                  return Err(Error::Config(format!("duplicate backend pattern '{name}'")));
               }
               wildcard.push((pattern, backend));
            },
            name => {
               let canonical = CanonicalHost::parse(name)
                  .map_err(|err| Error::Config(format!("backend pattern '{name}': {err}")))?;
               let pattern = canonical.as_str().to_owned();
               if !seen.insert(pattern.clone()) {
                  return Err(Error::Config(format!("duplicate backend pattern '{name}'")));
               }
               exact.push((pattern, backend));
            },
         }
      }

      wildcard.sort_by_key(|(pattern, _)| std::cmp::Reverse(pattern.len()));

      Ok(Self {
         exact,
         wildcard,
         fallback,
      })
   }

   /// `host` is already canonical, so it carries no port and renders an IPv6
   /// literal unbracketed. Splitting it on `:` would reduce `::1` to nothing.
   pub fn select(&self, host: &str) -> Option<Arc<Backend>> {
      for (pattern, backend) in &self.exact {
         if pattern == host {
            return Some(Arc::clone(backend));
         }
      }

      for (suffix, backend) in &self.wildcard {
         if host.ends_with(suffix.as_str()) {
            return Some(Arc::clone(backend));
         }
      }

      self.fallback.as_ref().map(Arc::clone)
   }

   /// Look up a backend by its configured name (exact string match against
   /// the pattern, including `*` and `*.domain` patterns).
   #[must_use]
   pub fn by_name(&self, name: &str) -> Option<Arc<Backend>> {
      self
         .exact
         .iter()
         .chain(&self.wildcard)
         .map(|(_, backend)| backend)
         .chain(&self.fallback)
         .find(|backend| backend.config.name == name)
         .map(Arc::clone)
   }

   #[must_use]
   pub fn certificate(&self, server_name: Option<&str>) -> Option<Arc<ServerConfig>> {
      let backend = match server_name {
         Some(name) => self.select(CanonicalHost::parse(name).ok()?.as_str()),
         None => self.fallback.clone(),
      }?;
      backend.tls.clone()
   }

   #[must_use]
   pub const fn is_empty(&self) -> bool {
      self.exact.is_empty() && self.wildcard.is_empty() && self.fallback.is_none()
   }
}
