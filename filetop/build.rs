use libbpf_cargo::SkeletonBuilder;
use std::{env, path::PathBuf};

const SRC: &str = "src/bpf/filetop.bpf.c";

fn main() {
    let mut out =
        PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script"));
    out.push("filetop.skel.rs");
    SkeletonBuilder::new()
        .source(SRC)
        .clang_args("-fno-stack-protector")
        .build_and_generate(&out)
        .unwrap();
    println!("cargo:rerun-if-changed={SRC}");
    println!("cargo:rerun-if-changed=src/bpf/filetop.h");
    println!("cargo:rerun-if-changed=src/bpf/stat.h");
}
