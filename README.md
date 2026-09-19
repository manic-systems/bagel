# bagel

Bagel is an HTTP proxy and SSH tarpit daemon that delays malicious scanners. It
reads configured evidence sources, applies durable escalation policies, and can
enforce bans through nftables. Its HTTP data plane adds a KDL rule engine with
rhai conditions, scorecards, challenges, mazes, crawler verification and paced
deception pages, and every hostile verdict it makes feeds the same escalation
policies.

## Why bagel

The project can be thought of as individual components that make up a bagel.

To start off, the HTTP plane is the counter. It sizes up each request and either
serves it, stalls it, or turns it away. Verified crawlers and allowlisted ranges
go through the hole and reach the backend untouched.

- The **schmear** is `smear`, a deceptive body written out slowly. It's spread
  thin, so `max-concurrent` runs out under load and the rest degrade to a drop.
- The **lox** is `tarpit`, sliced thin and served one piece at a time until
  `max-secs` expires.
- The **dough** is `deception`. Point `corpora` at some text and the markov
  generator produces as much filler as the maze asks for.
- The **seeds** are the trap paths, scattered over the surface and sticking to
  whatever touches them. Rules reach them through `trap["path"]`.
- The **kettle** is `maze`. Bagels are boiled before they're baked, and a crawler
  that walks into a generated page tree goes round in hot water for about as long.

`enforcement mode="required"` is an everything bagel. `mode="observe"` is a plain
one that only watches.

## Quickstart

Build it with `nix build` in the checkout, or `cargo build --release` with
`lld` and a `wasm32v1-none` target installed for the solver. Then print the
starter config and run it.

```sh
bagel config example > bagel.kdl
bagel-daemon --config bagel.kdl --check-config
bagel-daemon --config bagel.kdl --disable-firewall
```

The starter listens on `:8080`, proxies everything to `127.0.0.1:8081`,
smears anyone asking for `/.env` and counts those hits toward a drop. Point
`backends` at your app and set `client-ip-header` and `trusted-proxies` to
whatever sits in front of bagel, otherwise every visitor looks like the proxy.
`--disable-firewall` keeps bans in memory so you can try it without
`CAP_NET_ADMIN`. `curl localhost:8080/.env` gets a deceptive error page and
`localhost:9100/metrics` shows the rule that fired.

To gate something, add a challenge and a rule that uses it.

```kdl
policy {
    challenges {
        challenge "pow" runtime="pow-sha256" difficulty=16 duration=86400
    }
    rules {
        rule "probe" condition=#"path == "/.env""# action="smear"
        rule "tools" condition=#"user_agent.starts_with_any(["curl/", "python-requests/"])"# action="challenge" {
            challenges "pow"
        }
    }
}
```

A curl on `/` now gets the challenge page and a browser solves it once, then
carries a day-long cookie. Challenges and mazes sign their tokens, so generate
a key once with `bagel-daemon --generate-key`, keep it out of the config, and
pass it with `--key-seed-file`. Without one bagel makes a fresh key at every
start and every outstanding cookie dies with the restart.

On NixOS the flake exports `nixosModules.bagel`.

```nix
services.bagel = {
  enable = true;
  configFile = ./bagel.kdl;
  keySeedFile = config.age.secrets.bagel-key.path;
};
```

The module enables nftables, grants `CAP_NET_ADMIN` when `enforcementMode` is
`required`, which has to match the `enforcement` node in the file since the
module can't read KDL, and validates the config at build time so a bad file
fails the system build rather than the service.

## Configuration

One KDL file configures both planes, web nodes at the top level and the defense
plane under `defense { }`, see `examples/bagel.kdl`. `bagel config example`
prints a starting point, `bagel-daemon --config bagel.kdl` starts the daemon
and `--check-config` validates the file without starting anything. Rules,
scoring, the prelude, condition bindings, mazes and renderers are described in
[docs/policy.md](docs/policy.md), and the key and token design under mazes in
[docs/maze.md](docs/maze.md).

Every section is typed, so an unknown field, a repeated singleton, a wrongly
typed scalar or a bad snippet in `policy-dir` is a load error. Every rhai
condition is checked at load too, so a typo fails validation instead of the
first request. Rhai goes in a KDL raw string, `condition=#"path == "/x""#`, or
the multi-line `#"""` form, and the optional `(rhai)` annotation rejects
misspellings.

Mazes need a persistent key. Generate it once with `bagel-daemon
--generate-key`, then supply it through `--key-seed-file` or
`services.bagel.keySeedFile` on NixOS. Rotating it invalidates every
outstanding maze URL and challenge cookie.

Two rule features tie the planes together. `action="report" kind="tarball"`
emits a web offense the defense plane can count per address and escalate, and
`lease["active"]` is true while the client holds an active lease, so a rule
placed first can `deny` or `tarpit` it at the web layer. That's what makes the
ladder useful behind a CDN, where a kernel drop never reaches the client.

## Challenges

Put a `challenge-template` block inside a `backend` to match its site's colors.
Its properties override the top-level template for that backend, including
embedded cards and error pages. Optional `light` and `dark` blocks follow the
browser's color preference. Setting `color-scheme` to `light` or `dark` pins
the palette, while `light dark` follows the browser.

```kdl
backends {
    backend "git.example.com" {
        url "http://127.0.0.1:3000"
        challenge-template {
            color-scheme "light dark"
            radius "6px"
            light { bg "#fbfbfa"; card-bg "#ffffff"; fg "#1a1c1e"; accent "#a8481c" }
            dark { bg "#0f1113"; card-bg "#15171a"; fg "#e7e8e3"; accent "#ef9f56" }
        }
    }
}
```

A `challenge` rule replaces the page with an interstitial. A `check` rule
splices the solver into the proxied page instead, so the page stays usable
while the proof runs. `embed="hidden"`, the default, delivers only the solver,
and `embed="card"` also draws the card, inside a shadow root so neither
stylesheet reaches the other. An origin can place it with an empty
`<div id="bagel-challenge">`. An origin whose CSP blocks the runtime script or
the same-origin worker can't run the embedded widget, and those clients meet
the blocking wall on the next gated request.

The proof runs in a wasm module built from `bagel-solver` and driven by a Web
Worker. The page carries only an opaque handoff and the verify URL, and the
module unpacks the key and difficulty, searches nonces and seals the solution.
Every asset URL carries a `?v=` digest, so a new build never runs a cached
worker against a fresh module. Each challenge is issued its own vela rewrite of
the module from a pool prepared at startup, falling back to the static build,
and every build proves the static rewrite and three more seeds against the
native solver before it ships. The profile lives in `bagel_solver::host`.
Building needs `lld` for `wasm32v1-none`, shrinks with `wasm-opt` when
binaryen is available, and `BAGEL_SOLVER_WASM` substitutes a prebuilt module.

Two proofs are available. `pow-sha256` hashes once per attempt and
`difficulty` defaults to 16. `pow-scratch` walks a scratchpad of `memory` KiB,
a power of two from 64 to 1024 defaulting to 256, in a data-dependent order
and defaults `difficulty` to 10. Every attempt touches the whole pad, so a
batch solver gains little over a browser. `difficulty` counts leading zero bits
for both, so each bit doubles the work, and the two aren't comparable at equal
settings. Raise either one against a real browser rather than by arithmetic,
since an unsolvable setting locks every visitor out and looks identical to a
slow one.

A rule or threshold may add `difficulty=N` to demand more than the challenge's
own setting. A pass is sealed at the difficulty it was verified at, and a gate
accepts any pass at or above the level it asks for. `pow-sha256` may also
carry `gpu-difficulty` and `gpu-duration`. A browser with WebGPU then searches
the harder level in a compute shader and earns the longer token, everything
else solves `difficulty` in wasm, and `pow["level"]` says which. A software
adapter such as SwiftShader, or one whose first batch projects past two
seconds, is treated as no GPU so the harder level never lands on a CPU. A site that
wants the GPU-sized proof from everyone sets `difficulty` to that number and
`gpu-required=#true`, which shows a visitor without WebGPU a message instead
of a wasm spinner.

Each challenge key is bound to its session and request identity, and
redemption consumes it once, so a replayed proof can't issue another pass.
A pass is also sealed with the TLS stack that verified it, the native JA4 or
the family behind the edge's cipher list, so a token solved in a browser and
copied into a scraping client meets the challenge again on the first request.

## Dashboard

`contrib/grafana/bagel.json` is a Grafana dashboard over the exported metrics.
It expects a Prometheus datasource and a scrape job named `bagel`. This can
be imported as is.

> [!NOTE]
> For contributors, `nix/dashboard.nix` renders it and `nix flake check` fails
> when the two drift.

## Build features

ACME needs the `bagel-daemon` crate's `acme` feature and a TCP listener, and
an ACME configuration the build can't honor fails validation rather than
falling back to plaintext. Crawler verification by forward-confirmed reverse
DNS needs `fcrdns`, on by default, and a `crawlers` block in a build without
it fails validation rather than waving every claimed crawler through. Upstream
proxy connections are HTTP only for now.

## Reload and shutdown

SIGHUP reloads the web policy and carries signing keys, rate counters and
poison memory across. Defense configuration and listener or TLS settings need
a restart, and a rejected configuration leaves the running one in place.

Shutdown closes defense record intake first and drains what was already
queued, bounded by `drain-timeout-secs`. Web records the bounded queue had to
drop show up in `bagel_offenses_total{result="dropped"}`.

## Development

```sh
# Enter the development shell.
$ nix develop

# Run the workspace tests.
$ cargo test --locked --workspace --all-features
$ cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
$ nix flake check
```

The Nix checks build the package and validate the installed example. They also
exercise the NixOS module's maze config check both with and without a
configured key seed. None of them start a service or touch the host firewall.

Formatting needs a nightly `rustfmt`, since `.rustfmt.toml` sets nightly-only
options. The Nix devshell supplies one.

## License

EUPL-1.2, see [LICENSE](LICENSE).
