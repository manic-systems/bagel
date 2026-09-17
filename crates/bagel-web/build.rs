use std::{
   env,
   fs,
   path::{
      Path,
      PathBuf,
   },
   process::Command,
};

use bagel_solver::host::{
   compression,
   config,
   validate,
};
use vela::{
   delivery::artifact::{
      Encoding,
      Variant,
   },
   prepare::Prepared,
   worker::{
      self,
      Verifier,
   },
};

/// Rewrite a module without its custom sections. `wasm-opt` keeps
/// `target_features`, and nixpkgs builds with cargo-auditable, which injects a
/// `.dep-v0` section naming the crate and its version. Neither belongs in a
/// module served to every visitor.
fn strip_custom_sections(path: &Path) {
   let module = fs::read(path).expect("read the solver module");
   let (header, mut rest) = module.split_at(8);
   let mut out = header.to_vec();

   while let Some((&id, tail)) = rest.split_first() {
      let mut size = 0_usize;
      let mut shift = 0;
      let mut read = 0;
      loop {
         let byte = tail[read];
         assert!(
            shift < usize::BITS,
            "solver module has a malformed section length"
         );
         size |= usize::from(byte & 0x7F) << shift;
         shift += 7;
         read += 1;
         if byte & 0x80 == 0 {
            break;
         }
      }
      let (payload, next) = tail[read..].split_at(size);
      if id != 0 {
         out.push(id);
         out.extend_from_slice(&tail[..read]);
         out.extend_from_slice(payload);
      }
      rest = next;
   }

   fs::write(path, out).expect("write the stripped solver module");
}

fn obfuscate(verifier: &Verifier, path: &Path) {
   strip_custom_sections(path);
   let module = fs::read(path).expect("failed to read the solver module");
   let input_path = path.with_file_name("solver.input.wasm");
   fs::write(&input_path, &module).expect("failed to preserve the solver input");
   let prepared = Prepared::new(module, config(0)).expect("failed to prepare the solver profile");
   let original = fs::read(input_path).expect("failed to read the preserved solver input");

   for seed in [0, 1, 42, u64::MAX] {
      let variant = Variant::prepare(&prepared, seed, compression())
         .expect("failed to prepare a solver variant");
      validate(verifier, &original, variant.bytes(Encoding::Identity))
         .expect("failed to validate the solver variant");

      if seed == 0 {
         fs::write(path, variant.bytes(Encoding::Identity))
            .expect("failed to write the static solver");
         fs::write(
            path.with_file_name("solver.wasm.br"),
            variant.bytes(Encoding::Brotli),
         )
         .expect("failed to write the compressed static solver");
      }
   }
}

/// The browser solver is a wasm build of `bagel-solver`, embedded into the
/// binary. `BAGEL_SOLVER_WASM` points at a prebuilt module.
fn main() {
   if worker::entrypoint().expect("run the verification worker") {
      return;
   }
   let executable = env::current_exe().expect("locate the verification worker");
   println!(
      "cargo:rustc-env=BAGEL_VERIFY_WORKER={}",
      executable.display()
   );
   let verifier = Verifier::new(&executable, worker::Limits::default())
      .expect("configure the verification worker");
   let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR is set by cargo"));
   let dest = out_dir.join("solver.wasm");
   println!("cargo:rerun-if-env-changed=BAGEL_SOLVER_WASM");

   if let Ok(prebuilt) = env::var("BAGEL_SOLVER_WASM") {
      println!("cargo:rerun-if-changed={prebuilt}");
      fs::copy(&prebuilt, &dest).expect("copy prebuilt solver module");
      obfuscate(&verifier, &dest);
      return;
   }

   let crates = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is set"))
      .parent()
      .expect("bagel-web lives under crates/")
      .to_path_buf();
   let solver = crates.join("bagel-solver");
   println!("cargo:rerun-if-changed={}", solver.display());

   let target_dir = out_dir.join("solver-target");
   let status = Command::new(env::var("CARGO").expect("CARGO is set by cargo"))
      .args([
         "rustc",
         "--offline",
         "--ignore-rust-version",
         "--profile",
         "solver",
         "--crate-type",
         "cdylib",
         "--target",
         "wasm32v1-none",
      ])
      .arg("--manifest-path")
      .arg(solver.join("Cargo.toml"))
      .arg("--target-dir")
      .arg(&target_dir)
      .env_remove("RUSTFLAGS")
      .env_remove("CARGO_ENCODED_RUSTFLAGS")
      .env_remove("CARGO_BUILD_RUSTFLAGS")
      .env_remove("CARGO_BUILD_TARGET")
      .env_remove("CARGO_TARGET_DIR")
      .status()
      .expect("run cargo for the solver module");
   assert!(
      status.success(),
      "building bagel-solver for wasm32v1-none failed"
   );

   let built = target_dir
      .join("wasm32v1-none")
      .join("solver")
      .join("bagel_solver.wasm");
   let shrunk = Command::new("wasm-opt")
      .args(["-Oz", "--strip-debug", "--strip-producers"])
      .arg(&built)
      .arg("-o")
      .arg(&dest)
      .status();
   match shrunk {
      Ok(status) => assert!(status.success(), "wasm-opt failed on the solver module"),
      Err(err) => {
         assert!(
            err.kind() == std::io::ErrorKind::NotFound,
            "run wasm-opt: {err}"
         );
         fs::copy(&built, &dest).expect("copy built solver module");
      },
   }

   obfuscate(&verifier, &dest);
}
