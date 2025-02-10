use libbpf_cargo::SkeletonBuilder;
use std::env;

const SRC: &str = "src/bpf/bindsnoop.bpf.c";

fn main() {
    let out = env::current_dir()
        .unwrap()
        .join("src/bpf/bindsnoop.skel.rs");
    SkeletonBuilder::new()
        .source(SRC)
        .clang_args(["-fno-stack-protector"])
        .build_and_generate(&out)
        .unwrap();
    println!("cargo:rerun-if-changed={SRC}");
    println!("cargo:rerun-if-changed=src/bpf/bindsnoop.h");
}
