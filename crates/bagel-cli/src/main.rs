//! `bagel` admin CLI.

use std::{
   path::PathBuf,
   time::{
      Duration,
      SystemTime,
      UNIX_EPOCH,
   },
};

use anyhow::Context;
use bagel_admin::{
   Request,
   Response,
};
use pound::{
   Parse,
   complete::{
      Candidate,
      Partial,
   },
};

#[derive(Parse)]
#[pound(name = "bagel", help_if_empty)]
struct Cli {
   /// Path to the daemon admin socket.
   #[pound(
      long,
      short = 's',
      env = "BAGEL_ADMIN_SOCKET",
      default = { bagel_core::DEFAULT_ADMIN_SOCKET },
      global
   )]
   socket: PathBuf,

   /// Emit machine-readable JSON instead of formatted text.
   #[pound(long, global)]
   json: bool,

   #[pound(subcommand)]
   command: Command,
}

#[derive(Parse)]
enum Command {
   /// Show daemon status and counters.
   Status,
   /// Add a manual durable ban for an address or CIDR.
   #[pound(after_help = "Examples:\n  bagel block 203.0.113.0/24 --duration-secs 3600")]
   Block {
      network:       String,
      #[pound(long)]
      duration_secs: Option<u64>,
   },
   /// Remove manual and automatic bans for an address or CIDR.
   Unblock {
      #[pound(complete = complete_ban)]
      network: String,
   },
   /// List active durable enforcement leases.
   Bans,
   /// List configured defense policies.
   Policies,
   /// Rebuild Bagel's nftables table from durable leases.
   Reconcile,
   /// Configuration tooling that runs without the daemon.
   Config {
      #[pound(subcommand)]
      action: ConfigCommand,
   },
}

#[derive(Parse)]
enum ConfigCommand {
   /// Print a starter KDL configuration covering both planes.
   Example,
}

#[expect(clippy::print_stdout, reason = "the CLI writes its results to stdout")]
fn main() -> anyhow::Result<()> {
   caress::handle(Cli::SPEC);

   let cli = Cli::parse();

   if let Command::Config { action } = &cli.command {
      run_config(action);
      return Ok(());
   }

   let request = match &cli.command {
      Command::Status => Request::Status,
      Command::Block {
         network,
         duration_secs,
      } => {
         Request::Block {
            network:       network.clone(),
            duration_secs: *duration_secs,
         }
      },
      Command::Unblock { network } => {
         Request::Unblock {
            network: network.clone(),
         }
      },
      Command::Bans => Request::ListBans,
      Command::Policies => Request::ListPolicies,
      Command::Reconcile => Request::Reconcile,
      Command::Config { .. } => return Ok(()),
   };

   let runtime = tokio::runtime::Builder::new_current_thread()
      .enable_all()
      .build()?;
   let response = runtime
      .block_on(bagel_admin::query(&cli.socket, &request))
      .with_context(|| format!("cannot reach the bagel daemon at {}", cli.socket.display()))?;

   let is_error = matches!(response, Response::Error(_));
   if cli.json {
      println!("{}", serde_json::to_string_pretty(&response)?);
      if is_error {
         std::process::exit(1);
      }
   } else if let Response::Error(msg) = &response {
      return Err(anyhow::anyhow!("{msg}"));
   } else {
      print!("{response}");
   }

   Ok(())
}

fn complete_ban(partial: &Partial<'_, '_>, _typed: &str) -> Vec<Candidate> {
   let socket = partial
      .arg("--socket")
      .and_then(|given| given.last())
      .map(PathBuf::from)
      .or_else(|| std::env::var_os("BAGEL_ADMIN_SOCKET").map(PathBuf::from))
      .unwrap_or_else(|| PathBuf::from(bagel_core::DEFAULT_ADMIN_SOCKET));

   let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
      .enable_all()
      .build()
   else {
      return Vec::new();
   };
   let query = bagel_admin::query(&socket, &Request::ListBans);
   let answer =
      runtime.block_on(async { tokio::time::timeout(Duration::from_millis(500), query).await });
   let Ok(Ok(Response::Bans(bans))) = answer else {
      return Vec::new();
   };

   let now = SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .map_or(0, |since| since.as_secs());
   bans
      .into_iter()
      .map(|ban| {
         let expiry = ban.expires_at.map_or_else(
            || "permanent".to_owned(),
            |at| {
               let left = at.saturating_sub(now);
               format!("expires in {}h{:02}m", left / 3600, left % 3600 / 60)
            },
         );
         Candidate::new(ban.network).help(format!("{}, {expiry}", ban.policy))
      })
      .collect()
}

#[expect(
   clippy::print_stdout,
   reason = "printing the example config to stdout is what the subcommand is for"
)]
fn run_config(action: &ConfigCommand) {
   match action {
      ConfigCommand::Example => print!("{}", include_str!("../../../examples/bagel.kdl")),
   }
}
