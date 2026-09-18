use std::{
   collections::{
      HashMap,
      HashSet,
   },
   net::{
      IpAddr,
      SocketAddr,
   },
   sync::Arc,
};

use http::{
   Request,
   Version,
};
use rhai::{
   AST,
   ASTFlags,
   ASTNode,
   Array,
   Dynamic,
   Engine,
   EvalAltResult,
   Expr,
   FnCallExpr,
   ImmutableString,
   Module,
   Position,
   Scope,
   Stmt,
   packages::{
      ArithmeticPackage,
      BasicArrayPackage,
      BasicMapPackage,
      BasicStringPackage,
      LanguageCorePackage,
      LogicPackage,
      MoreStringPackage,
      Package,
   },
};

use crate::{
   body::Body,
   claim::Claim,
   config::policy::PreludeConfig,
   fingerprint::Capture,
   http2::Http2Fingerprint,
   net::{
      IpNetTrie,
      census::CensusSnapshot,
      rate::RateSnapshot,
   },
   tls::TlsFingerprint,
   visit::VisitSnapshot,
};

#[must_use]
pub fn build_engine() -> Engine {
   let mut engine = Engine::new_raw();

   for package in [
      LanguageCorePackage::new().as_shared_module(),
      ArithmeticPackage::new().as_shared_module(),
      LogicPackage::new().as_shared_module(),
      BasicStringPackage::new().as_shared_module(),
      MoreStringPackage::new().as_shared_module(),
      BasicArrayPackage::new().as_shared_module(),
      BasicMapPackage::new().as_shared_module(),
   ] {
      engine.register_global_module(package);
   }

   engine.set_max_expr_depths(64, 32);
   engine.set_max_operations(10_000);
   engine.set_max_string_size(4096);

   engine.register_fn("starts_with_any", |text: &str, items: Array| {
      any_item(&items, |item| text.starts_with(item))
   });
   engine.register_fn("ends_with_any", |text: &str, items: Array| {
      any_item(&items, |item| text.ends_with(item))
   });
   engine.register_fn("contains_any", |text: &str, items: Array| {
      any_item(&items, |item| text.contains(item))
   });
   engine.register_fn("param", query_param);

   engine
}

fn any_item(items: &Array, matches: impl Fn(&str) -> bool) -> Result<bool, Box<EvalAltResult>> {
   for item in items {
      let Some(text) = item.read_lock::<ImmutableString>() else {
         return Err(Box::new(EvalAltResult::ErrorMismatchDataType(
            "string".to_owned(),
            item.type_name().to_owned(),
            Position::NONE,
         )));
      };
      if matches(&text) {
         return Ok(true);
      }
   }
   Ok(false)
}

/// First value of `name` in a query string, form-decoded, or empty when the
/// parameter is absent or has no value.
fn query_param(query: &str, name: &str) -> ImmutableString {
   query
      .split('&')
      .map(|pair| pair.split_once('=').unwrap_or((pair, "")))
      .find(|(key, _)| form_decode(key) == name)
      .map_or_else(ImmutableString::new, |(_, value)| form_decode(value).into())
}

fn form_decode(text: &str) -> String {
   let bytes = text.as_bytes();
   let mut out = Vec::with_capacity(bytes.len());
   let mut at = 0;
   while at < bytes.len() {
      let hex = bytes
         .get(at + 1..at + 3)
         .filter(|_| bytes[at] == b'%')
         .and_then(|pair| str::from_utf8(pair).ok())
         .and_then(|pair| u8::from_str_radix(pair, 16).ok());
      if let Some(byte) = hex {
         out.push(byte);
         at += 3;
      } else {
         out.push(if bytes[at] == b'+' { b' ' } else { bytes[at] });
         at += 1;
      }
   }
   String::from_utf8_lossy(&out).into_owned()
}

/// Variables available during condition evaluation.
#[derive(Clone)]
pub struct ConditionContext {
   pub host:             String,
   pub method:           String,
   pub path:             String,
   pub query:            String,
   pub user_agent:       String,
   pub remote_address:   String,
   pub remote_ip:        Option<IpAddr>,
   pub http_version:     String,
   pub headers:          HashMap<String, String>,
   pub fp:               HashMap<String, String>,
   /// Stable transport identity behind `fp`, when any source supplied one.
   pub fp_identity:      Option<String>,
   /// TLS stack a pass may be bound to, see [`TlsFingerprint::stack`].
   pub stack:            Option<String>,
   /// Browser the user agent claims to be, `None` for tools and crawlers.
   pub claim:            Option<Claim>,
   /// Census counts for this claim and identity, `None` when either is
   /// missing or the census is saturated.
   pub census:           Option<CensusSnapshot>,
   /// Environment profile the solver sealed into the clearance token.
   pub probe:            Option<u64>,
   /// Highest proof-of-work level among the token's passes.
   pub pow_level:        Option<u32>,
   /// Census counts for this claim and probe profile.
   pub probe_census:     Option<CensusSnapshot>,
   /// Pre-computed network membership results: `network_name` -> bool.
   pub network_results:  HashMap<String, bool>,
   /// Normal rate snapshot, `None` when no client network resolved.
   pub rate:             Option<RateSnapshot>,
   /// Challenge passes by this host and source network in minute buckets,
   /// `None` when no client network resolved.
   pub solves:           Option<RateSnapshot>,
   /// What this clearance session has done with its pages, `None` without a
   /// session cookie.
   pub visit:            Option<VisitSnapshot>,
   pub poison_returned:  bool,
   pub crawler_verified: bool,
   pub lease_active:     bool,
   /// Bagel trap classification, `None` until the daemon attaches a classifier.
   pub trap:             Option<TrapVerdict>,
}

/// What bagel's signature classifier said about the request. `reason` is
/// `path`, `user_agent` or `impersonator`, and `category` is the report
/// bucket of a path trap.
#[derive(Clone, Default)]
pub struct TrapVerdict {
   pub reason:   Option<&'static str>,
   pub category: Option<&'static str>,
}

impl ConditionContext {
   #[must_use]
   pub fn scope(&self) -> Scope<'static> {
      let mut scope = Scope::new();

      scope.push_constant("host", self.host.clone());
      scope.push_constant("method", self.method.clone());
      scope.push_constant("path", self.path.clone());
      scope.push_constant("query", self.query.clone());
      scope.push_constant("user_agent", self.user_agent.clone());
      scope.push_constant("remote_address", self.remote_address.clone());
      scope.push_constant("http_version", self.http_version.clone());

      let headers_map: rhai::Map = self
         .headers
         .iter()
         .map(|(key, val)| (key.clone().into(), Dynamic::from(val.clone())))
         .collect();
      scope.push_constant("headers", headers_map);

      let fp_map: rhai::Map = self
         .fp
         .iter()
         .map(|(key, val)| (key.clone().into(), Dynamic::from(val.clone())))
         .collect();
      scope.push_constant("fp", fp_map);

      let net_map: rhai::Map = self
         .network_results
         .iter()
         .map(|(key, val)| (key.clone().into(), Dynamic::from(*val)))
         .collect();
      scope.push_constant("networks", net_map);

      let rate = self.rate;
      let mut rate_map = rhai::Map::new();
      rate_map.insert("available".into(), Dynamic::from(rate.is_some()));
      rate_map.insert("1s".into(), count(rate.map(|snap| snap.last_1)));
      rate_map.insert("10s".into(), count(rate.map(|snap| snap.last_10)));
      rate_map.insert("60s".into(), count(rate.map(|snap| snap.last_60)));
      scope.push_constant("rate", rate_map);

      let claim = self.claim;
      let mut claim_map = rhai::Map::new();
      claim_map.insert("browser".into(), Dynamic::from(claim.is_some()));
      claim_map.insert(
         "family".into(),
         text(claim.map(|claim| claim.family.to_string())),
      );
      claim_map.insert("major".into(), count(claim.map(|claim| claim.major)));
      claim_map.insert(
         "platform".into(),
         text(claim.map(|claim| claim.platform.to_string())),
      );
      claim_map.insert(
         "mobile".into(),
         Dynamic::from(claim.is_some_and(|claim| claim.mobile)),
      );
      claim_map.insert(
         "stack".into(),
         text(claim.map(|claim| claim.stack().to_owned())),
      );
      scope.push_constant("claim", claim_map);

      let census = self.census;
      let probe_census = self.probe_census;
      let mut census_map = rhai::Map::new();
      census_map.insert("available".into(), Dynamic::from(census.is_some()));
      census_map.insert(
         "claim_networks".into(),
         count(census.map(|snap| snap.claim_networks)),
      );
      census_map.insert(
         "pair_networks".into(),
         count(census.map(|snap| snap.pair_networks)),
      );
      census_map.insert(
         "pair_permille".into(),
         count(census.map(|snap| snap.pair_permille())),
      );
      census_map.insert(
         "probe_available".into(),
         Dynamic::from(probe_census.is_some()),
      );
      census_map.insert(
         "probe_networks".into(),
         count(probe_census.map(|snap| snap.pair_networks)),
      );
      census_map.insert(
         "probe_permille".into(),
         count(probe_census.map(|snap| snap.pair_permille())),
      );
      scope.push_constant("census", census_map);

      let mut probe_map = rhai::Map::new();
      probe_map.insert("available".into(), Dynamic::from(self.probe.is_some()));
      probe_map.insert(
         "profile".into(),
         text(self.probe.map(|probe| format!("{probe:016x}"))),
      );
      scope.push_constant("probe", probe_map);

      let mut pow_map = rhai::Map::new();
      pow_map.insert("available".into(), Dynamic::from(self.pow_level.is_some()));
      pow_map.insert("level".into(), count(self.pow_level));
      scope.push_constant("pow", pow_map);

      let solves = self.solves;
      let mut solves_map = rhai::Map::new();
      solves_map.insert("available".into(), Dynamic::from(solves.is_some()));
      solves_map.insert("10m".into(), count(solves.map(|snap| snap.last_10)));
      solves_map.insert("60m".into(), count(solves.map(|snap| snap.last_60)));
      scope.push_constant("solves", solves_map);

      let visit = self.visit;
      let mut visit_map = rhai::Map::new();
      visit_map.insert("available".into(), Dynamic::from(visit.is_some()));
      visit_map.insert(
         "rendered".into(),
         Dynamic::from(visit.is_some_and(|snap| snap.rendered)),
      );
      visit_map.insert(
         "greedy".into(),
         Dynamic::from(visit.is_some_and(|snap| snap.greedy)),
      );
      visit_map.insert("documents".into(), count(visit.map(|snap| snap.documents)));
      visit_map.insert("pages".into(), count(visit.map(|snap| snap.pages)));
      visit_map.insert("assets".into(), count(visit.map(|snap| snap.assets)));
      scope.push_constant("visit", visit_map);

      let mut poison_map = rhai::Map::new();
      poison_map.insert("returned".into(), Dynamic::from(self.poison_returned));
      scope.push_constant("poison", poison_map);

      let mut lease_map = rhai::Map::new();
      lease_map.insert("active".into(), Dynamic::from(self.lease_active));
      scope.push_constant("lease", lease_map);

      let mut crawler_map = rhai::Map::new();
      crawler_map.insert("verified".into(), Dynamic::from(self.crawler_verified));
      scope.push_constant("crawler", crawler_map);

      let trap = self.trap.clone().unwrap_or_default();
      let mut trap_map = rhai::Map::new();
      trap_map.insert("available".into(), Dynamic::from(self.trap.is_some()));
      trap_map.insert("any".into(), Dynamic::from(trap.reason.is_some()));
      for reason in ["path", "user_agent", "impersonator"] {
         trap_map.insert(reason.into(), Dynamic::from(trap.reason == Some(reason)));
      }
      trap_map.insert("category".into(), text(trap.category.map(str::to_owned)));
      scope.push_constant("trap", trap_map);

      scope
   }

   pub fn from_request(req: &Request<Body>) -> Self {
      // HeaderName is already lowercase-normalized by the http crate
      let headers: HashMap<String, String> = req
         .headers()
         .iter()
         .map(|(name, val)| {
            (
               name.as_str().to_owned(),
               val.to_str().unwrap_or("").to_owned(),
            )
         })
         .collect();

      let user_agent = headers.get("user-agent").cloned().unwrap_or_default();
      let host = headers.get("host").cloned().unwrap_or_default();

      let remote_address = req
         .extensions()
         .get::<SocketAddr>()
         .map(|sa| sa.ip().to_string())
         .unwrap_or_default();

      let remote_ip = req.extensions().get::<SocketAddr>().map(SocketAddr::ip);

      let http_version = match req.version() {
         Version::HTTP_09 => "HTTP/0.9",
         Version::HTTP_10 => "HTTP/1.0",
         Version::HTTP_11 => "HTTP/1.1",
         Version::HTTP_2 => "HTTP/2.0",
         Version::HTTP_3 => "HTTP/3.0",
         _ => "unknown",
      };

      let tls = req.extensions().get::<TlsFingerprint>();
      let fp_identity = tls.and_then(TlsFingerprint::identity);
      let stack = tls.and_then(TlsFingerprint::stack);
      let mut fp = tls.map_or_else(
         || TlsFingerprint::default().policy_fields(),
         TlsFingerprint::policy_fields,
      );
      let http2 = req
         .extensions()
         .get::<Capture<Http2Fingerprint>>()
         .cloned()
         .unwrap_or_default();
      fp.insert("http2_status".to_owned(), http2.to_string());
      if let Capture::Complete(connection) = http2 {
         fp.extend(connection.policy_fields());
      }

      Self {
         host,
         method: req.method().as_str().to_owned(),
         path: req.uri().path().to_owned(),
         query: req.uri().query().unwrap_or("").to_owned(),
         claim: Claim::parse(&user_agent),
         user_agent,
         remote_address,
         remote_ip,
         http_version: http_version.to_owned(),
         headers,
         fp,
         fp_identity,
         stack,
         census: None,
         probe: None,
         probe_census: None,
         pow_level: None,
         network_results: HashMap::new(),
         rate: None,
         solves: None,
         visit: None,
         poison_returned: false,
         crawler_verified: false,
         lease_active: false,
         trap: None,
      }
   }

   /// Clone this context with `context` rule request headers merged in, so
   /// the subtree evaluates against the mutated request.
   #[must_use]
   pub fn with_request_headers(&self, headers: &http::HeaderMap) -> Self {
      let mut ctx = self.clone();
      for (name, value) in headers {
         ctx.headers.insert(
            name.as_str().to_owned(),
            value.to_str().unwrap_or("").to_owned(),
         );
      }
      if let Some(ua) = ctx.headers.get("user-agent") {
         ctx.user_agent = ua.clone();
      }
      if let Some(host) = ctx.headers.get("host") {
         ctx.host = host.clone();
      }
      ctx
   }

   #[expect(
      clippy::iter_over_hash_type,
      reason = "network membership does not depend on map iteration order"
   )]
   pub fn compute_network_membership(&mut self, networks: &HashMap<String, Arc<IpNetTrie>>) {
      if let Some(ip) = self.remote_ip {
         for (name, trie) in networks {
            self.network_results.insert(name.clone(), trie.contains(ip));
         }
      }
   }
}

/// Request bindings every condition may name. Anything else left unresolved
/// after constant folding is a typo, caught at load rather than on the first
/// request.
const BINDINGS: [&str; 21] = [
   "host",
   "method",
   "path",
   "query",
   "user_agent",
   "remote_address",
   "http_version",
   "headers",
   "fp",
   "networks",
   "rate",
   "claim",
   "census",
   "probe",
   "pow",
   "solves",
   "visit",
   "poison",
   "lease",
   "crawler",
   "trap",
];

/// Functions the engine handles as keywords, so they are absent from its
/// registered signatures.
const KEYWORD_FUNCTIONS: [&str; 10] = [
   "Fn",
   "call",
   "curry",
   "type_of",
   "is_def_fn",
   "is_def_var",
   "is_shared",
   "eval",
   "print",
   "debug",
];

/// The policy's rhai prelude, `const` values and `fn` helpers.
///
/// Constants fold into each condition at compile time and are also registered
/// as engine globals for the uses rhai cannot fold.
pub struct Prelude {
   constants:      Scope<'static>,
   constant_names: HashSet<String>,
   functions:      HashSet<(String, usize)>,
   lib:            AST,
}

impl Prelude {
   pub fn new(engine: &mut Engine, sources: &[PreludeConfig]) -> Result<Self, String> {
      let script = sources
         .iter()
         .map(|source| source.script.as_ref())
         .collect::<Vec<_>>()
         .join("\n");
      let prefix = |err: &dyn std::fmt::Display| format!("prelude: {err}");

      let mut constants = Scope::new();
      let first = engine.compile(&script).map_err(|err| prefix(&err))?;
      engine
         .run_ast_with_scope(&mut constants, &first)
         .map_err(|err| prefix(&err))?;

      let mut constant_names = HashSet::new();
      for statement in first.statements() {
         let Stmt::Var(declaration, flags, position) = statement else {
            continue;
         };
         let name = declaration.0.name.as_str();
         if !flags.contains(ASTFlags::CONSTANT) {
            return Err(format!(
               "prelude: '{name}' is a variable at {position}, the top level may only declare \
                const and fn"
            ));
         }
         if !constant_names.insert(name.to_owned()) {
            return Err(format!(
               "prelude: duplicate constant '{name}' at {position}"
            ));
         }
      }

      let mut globals = Module::new();
      for (name, _, value) in constants.iter() {
         globals.set_var(name, value);
      }
      engine.register_global_module(globals.into());

      let lib = engine
         .compile_with_scope(&constants, &script)
         .map_err(|err| prefix(&err))?
         .clone_functions_only();
      let mut functions: HashSet<(String, usize)> = engine
         .gen_fn_signatures(true)
         .iter()
         .filter_map(|signature| signature_arity(signature))
         .collect();
      functions.extend(
         lib.iter_functions()
            .map(|function| (function.name.to_owned(), function.params.len())),
      );

      let prelude = Self {
         constants,
         constant_names,
         functions,
         lib,
      };
      prelude.check(&prelude.lib).map_err(|err| prefix(&err))?;
      Ok(prelude)
   }

   pub fn compile(&self, engine: &Engine, expr: &str) -> Result<AST, String> {
      let ast = engine
         .compile_expression_with_scope(&self.constants, expr)
         .map_err(|err| format!("condition compile error: {err}"))?
         .merge(&self.lib);
      self.check(&ast)?;
      Ok(ast)
   }

   fn check(&self, ast: &AST) -> Result<(), String> {
      let mut problem = None;
      ast.walk(&mut |path| {
         let (found, position) = match path.last() {
            Some(ASTNode::Expr(Expr::Variable(access, _, position))) if access.0.is_none() => {
               let name = access.1.as_str();
               let known = BINDINGS.contains(&name) || self.constant_names.contains(name);
               (
                  (!known).then(|| format!("unknown variable '{name}'")),
                  *position,
               )
            },
            Some(
               ASTNode::Expr(Expr::FnCall(call, position))
               | ASTNode::Stmt(Stmt::FnCall(call, position)),
            ) => (self.unknown_call(call, call.args.len()), *position),
            Some(ASTNode::Expr(Expr::MethodCall(call, position))) => {
               (self.unknown_call(call, call.args.len() + 1), *position)
            },
            _ => (None, Position::NONE),
         };
         let Some(message) = found else {
            return true;
         };
         problem = Some(format!("{message} at {position}"));
         false
      });
      problem.map_or(Ok(()), Err)
   }

   fn unknown_call(&self, call: &FnCallExpr, arity: usize) -> Option<String> {
      let known = call.op_token.is_some()
         || call.name.contains('$')
         || KEYWORD_FUNCTIONS.contains(&call.name.as_str())
         || self.functions.contains(&(call.name.to_string(), arity));
      (!known).then(|| format!("unknown function '{}' taking {arity} arguments", call.name))
   }
}

/// Name and parameter count of one `Engine::gen_fn_signatures` entry, such
/// as `starts_with(string: string, match_string: string) -> bool`.
fn signature_arity(signature: &str) -> Option<(String, usize)> {
   let (name, rest) = signature.split_once('(')?;
   let mut depth = 0_usize;
   let mut params = 0_usize;
   let mut seen_param = false;
   for ch in rest.chars() {
      match ch {
         '(' | '<' | '[' => depth += 1,
         ')' | '>' | ']' if depth > 0 => depth -= 1,
         ')' => break,
         ',' if depth == 0 => params += 1,
         _ if !ch.is_whitespace() => seen_param = true,
         _ => {},
      }
   }
   Some((name.to_owned(), params + usize::from(seen_param)))
}

/// A count that is `()` when its source is absent, so any comparison against
/// it is false and conditions need no availability guard.
fn count(value: Option<impl Into<i64>>) -> Dynamic {
   value.map_or(Dynamic::UNIT, |value| Dynamic::from(value.into()))
}

fn text(value: Option<String>) -> Dynamic {
   value.map_or(Dynamic::UNIT, Dynamic::from)
}
