fn main() {
    #[cfg(target_os = "linux")]
    {
        let manifest_dir = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
        let workspace_dir = manifest_dir.parent().unwrap().parent().unwrap();
        let ebpf_dir = workspace_dir.join("crates").join("silo-ebpf");

        aya_build::build_ebpf(
            [aya_build::Package {
                name: "silo-ebpf",
                root_dir: ebpf_dir.to_str().expect("non-UTF-8 path"),
                no_default_features: false,
                features: &[],
            }],
            aya_build::Toolchain::Nightly,
        )
        .expect("failed to build silo-ebpf");

        println!("cargo:rerun-if-changed=../silo-ebpf/src");
        println!("cargo:rerun-if-changed=../silo-ebpf/Cargo.toml");
    }
}
