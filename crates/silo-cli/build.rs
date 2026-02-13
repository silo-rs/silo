use std::path::PathBuf;
use std::{env, fs};

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let workspace_dir = manifest_dir.parent().unwrap().parent().unwrap();
    let profile = env::var("PROFILE").unwrap();

    build_bind_lib(&out_dir, workspace_dir, &profile);

    #[cfg(target_os = "linux")]
    build_ebpf(workspace_dir, &out_dir);
}

fn build_bind_lib(out_dir: &std::path::Path, workspace_dir: &std::path::Path, profile: &str) {
    let lib_name = lib_name();
    let lib_path = workspace_dir.join("target").join(profile).join(lib_name);

    if lib_path.exists() {
        fs::copy(&lib_path, out_dir.join(lib_name)).expect("failed to copy dylib");
    } else {
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

        let built = tmp_target.join(profile).join(lib_name);
        fs::copy(&built, out_dir.join(lib_name)).expect("failed to copy dylib");
    }

    println!("cargo:rerun-if-changed=../silo-bind/src");
    println!("cargo:rerun-if-changed=../silo-bind/Cargo.toml");
    println!("cargo:rerun-if-changed={}", lib_path.display());
}

#[cfg(target_os = "linux")]
fn build_ebpf(workspace_dir: &std::path::Path, out_dir: &std::path::Path) {
    let ebpf_manifest = workspace_dir
        .join("crates")
        .join("silo-ebpf")
        .join("Cargo.toml");

    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_else(|_| "x86_64".into());
    let endian = env::var("CARGO_CFG_TARGET_ENDIAN").unwrap_or_else(|_| "little".into());
    let bpf_prefix = if endian == "big" { "bpfeb" } else { "bpfel" };
    let target = format!("{bpf_prefix}-unknown-none");

    let target_dir = out_dir.join("silo-ebpf");

    let mut cmd = std::process::Command::new("rustup");
    cmd.args(["run", "nightly", "cargo", "build"]);
    cmd.arg("--manifest-path").arg(&ebpf_manifest);
    cmd.args([
        "-Z",
        "build-std=core",
        "--bins",
        "--release",
        "--target",
        &target,
        "--target-dir",
    ]);
    cmd.arg(&target_dir);

    // RUSTFLAGS: set bpf_target_arch cfg, debuginfo, and BTF linking
    let sep = "\x1f";
    let rustflags = format!(
        "--cfg=bpf_target_arch=\"{target_arch}\"{sep}-Cdebuginfo=2{sep}-Clink-arg=--btf"
    );
    cmd.env("CARGO_ENCODED_RUSTFLAGS", &rustflags);
    cmd.env_remove("RUSTC");
    cmd.env_remove("RUSTC_WORKSPACE_WRAPPER");

    let result = cmd.status();
    match result {
        Ok(status) if status.success() => {
            let binary = target_dir.join(&target).join("release").join("silo-ebpf");
            if binary.exists() {
                fs::copy(&binary, out_dir.join("silo-ebpf"))
                    .expect("failed to copy eBPF binary to OUT_DIR");
            } else {
                println!(
                    "cargo:warning=eBPF binary not found at {}",
                    binary.display()
                );
                fs::write(out_dir.join("silo-ebpf"), b"").ok();
            }
        }
        Ok(status) => {
            println!(
                "cargo:warning=eBPF build failed (exit {status}). eBPF backend will not be available."
            );
            fs::write(out_dir.join("silo-ebpf"), b"").ok();
        }
        Err(e) => {
            println!(
                "cargo:warning=eBPF build failed ({e}). eBPF backend will not be available."
            );
            fs::write(out_dir.join("silo-ebpf"), b"").ok();
        }
    }

    println!("cargo:rerun-if-changed=../silo-ebpf/src");
    println!("cargo:rerun-if-changed=../silo-ebpf/Cargo.toml");
}

fn lib_name() -> &'static str {
    if cfg!(target_os = "macos") {
        "libsilo_bind.dylib"
    } else {
        "libsilo_bind.so"
    }
}
