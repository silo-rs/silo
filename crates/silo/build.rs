use std::path::PathBuf;
use std::{env, fs};

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let workspace_dir = manifest_dir.parent().unwrap().parent().unwrap();
    let profile = env::var("PROFILE").unwrap();

    let lib_name = lib_name();
    let lib_path = workspace_dir.join("target").join(&profile).join(lib_name);

    // Fast path: dylib already built (workspace build or prior `cargo build -p silo-bind`)
    if lib_path.exists() {
        fs::copy(&lib_path, out_dir.join(lib_name)).expect("failed to copy dylib");
    } else {
        // Fallback: build silo-bind with a separate target-dir to avoid cargo lock deadlock
        let cargo = env::var("CARGO").unwrap_or_else(|_| "cargo".into());
        let tmp_target = out_dir.join("silo-bind-build");

        let mut cmd = std::process::Command::new(&cargo);
        cmd.args(["build", "-p", "silo-bind"])
            .arg("--manifest-path")
            .arg(workspace_dir.join("Cargo.toml"))
            .arg("--target-dir")
            .arg(&tmp_target);

        if profile == "release" {
            cmd.arg("--release");
        }

        let status = cmd.status().expect("failed to build silo-bind");
        assert!(status.success(), "silo-bind build failed");

        let built = tmp_target.join(&profile).join(lib_name);
        fs::copy(&built, out_dir.join(lib_name)).expect("failed to copy dylib");
    }

    println!("cargo:rerun-if-changed=../silo-bind/src");
    println!("cargo:rerun-if-changed=../silo-bind/Cargo.toml");
}

fn lib_name() -> &'static str {
    if cfg!(target_os = "macos") {
        "libsilo_bind.dylib"
    } else {
        "libsilo_bind.so"
    }
}
