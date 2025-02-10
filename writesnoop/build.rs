use anyhow::Result;
use libbpf_cargo::SkeletonBuilder;
use std::env::{current_dir};

const SRC: &str = "src/bpf/writesnoop.bpf.c";

fn main() -> Result<()> {
    let mut out = current_dir()?;
    out.push("src/bpf/writesnoop.skel.rs");
    SkeletonBuilder::new()
        .source(SRC)
        .clang_args(["-fno-stack-protector"])
        .build_and_generate(&out)
        .unwrap();
    println!("cargo:rerun-if-changed={SRC}");
    Ok(())
}
