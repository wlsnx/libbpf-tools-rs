use libbpf_cargo::SkeletonBuilder;
use std::env::{current_dir};

const SRC: &str = "src/bpf/sslsnoop.bpf.c";

fn main() {
    let mut out = current_dir().unwrap();
    out.push("src/bpf/sslsnoop.skel.rs");
    SkeletonBuilder::new()
        .source(SRC)
        .clang_args(["-fno-stack-protector"])
        .build_and_generate(&out)
        .unwrap();
    println!("cargo:rerun-if-changed={SRC}");
    println!("cargo:rerun-if-changed=src/bpf/sslsnoop.h");
}
