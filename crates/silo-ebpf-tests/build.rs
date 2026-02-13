fn main() {
    #[cfg(target_os = "linux")]
    {
        use std::path::PathBuf;
        use std::{env, fs};

        let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
        let workspace_dir = manifest_dir.parent().unwrap().parent().unwrap();
        let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

        let ebpf_manifest = workspace_dir
            .join("crates")
            .join("silo-ebpf")
            .join("Cargo.toml");

        let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_else(|_| "x86_64".into());
        let endian = env::var("CARGO_CFG_TARGET_ENDIAN").unwrap_or_else(|_| "little".into());
        let bpf_prefix = if endian == "big" { "bpfeb" } else { "bpfel" };
        let target = format!("{bpf_prefix}-unknown-none");

        let target_dir = out_dir.join("silo-ebpf-build");

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

        let sep = "\x1f";
        let rustflags = format!(
            "--cfg=bpf_target_arch=\"{target_arch}\"{sep}-Cdebuginfo=2{sep}-Clink-arg=--btf"
        );
        cmd.env("CARGO_ENCODED_RUSTFLAGS", &rustflags);
        cmd.env_remove("RUSTC");
        cmd.env_remove("RUSTC_WORKSPACE_WRAPPER");
        cmd.env_remove("CARGO");
        cmd.env_remove("CARGO_MAKEFLAGS");

        let result = cmd.output();
        match result {
            Ok(output) if output.status.success() => {
                let binary = target_dir.join(&target).join("release").join("silo-ebpf");
                if binary.exists() {
                    let meta = fs::metadata(&binary).unwrap();
                    println!("cargo:warning=eBPF binary: {} bytes", meta.len());
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
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                println!(
                    "cargo:warning=eBPF build failed (exit {}). Tests will be skipped at runtime.",
                    output.status
                );
                for line in stderr.lines().take(20) {
                    println!("cargo:warning=  {line}");
                }
                fs::write(out_dir.join("silo-ebpf"), b"").ok();
            }
            Err(e) => {
                println!(
                    "cargo:warning=eBPF build failed ({e}). Tests will be skipped at runtime."
                );
                fs::write(out_dir.join("silo-ebpf"), b"").ok();
            }
        }

        println!("cargo:rerun-if-changed=../silo-ebpf/src");
        println!("cargo:rerun-if-changed=../silo-ebpf/Cargo.toml");
    }
}
