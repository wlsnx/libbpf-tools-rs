use libbpf_cargo::SkeletonBuilder;
use std::{env, fs}; // Removed unused PathBuf import

const SRC: &str = "src/bpf/filetop.bpf.c";

fn main() {
    let mut out = env::current_dir().expect("Failed to get current directory");
    out.push("src/bpf");

    // 确保输出目录存在
    fs::create_dir_all(&out).expect("Failed to create output directory");

    out.push("filetop.skel.rs");

    SkeletonBuilder::new()
        .source(SRC)
        .clang_args(["-fno-stack-protector"])
        .build_and_generate(&out)
        .unwrap();
    println!("cargo:rerun-if-changed={SRC}");
    println!("cargo:rerun-if-changed=src/bpf/filetop.h");
    println!("cargo:rerun-if-changed=src/bpf/stat.h");
}
