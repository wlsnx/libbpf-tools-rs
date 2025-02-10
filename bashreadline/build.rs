use libbpf_cargo::SkeletonBuilder;
use std::env::current_dir;

const SRC: &str = "src/bpf/bashreadline.bpf.c";

fn main() {
    let out = current_dir().unwrap().join("src/bpf/bashreadline.skel.rs");
    SkeletonBuilder::new()
        .source(SRC)
        .clang_args(["-fno-stack-protector"])
        .build_and_generate(&out)
        .unwrap();
    println!("cargo:rerun-if-changed={SRC}");
    println!("cargo:rerun-if-changed=src/bpf/bashreadline.h");
}
