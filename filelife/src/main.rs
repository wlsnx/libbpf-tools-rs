use anyhow::Result;
use clap::Parser;
use libbpf_rs::{
    skel::{OpenSkel, Skel, SkelBuilder},
    RingBufferBuilder,
};
use std::{ffi::CStr, mem::MaybeUninit, time::Duration};

mod filelife {
    include!("bpf/filelife.skel.rs");
}

use filelife::*;

#[derive(Debug, Parser)]
#[command(about = "Trace the lifespan of short-lived files.")]
struct Command {
    #[arg(short)]
    verbose: bool,
    #[arg(short)]
    pid: Option<i32>,
}

fn handle_event(data: &[u8]) -> i32 {
    let event = unsafe { &*(data.as_ptr() as *const types::event) };

    let now = chrono::Local::now().format("%H:%M:%S");

    println!(
        "{:<8} {:<6} {:<16} {:<7.2} {}",
        now,
        event.tgid,
        CStr::from_bytes_until_nul(&event.task)
            .unwrap()
            .to_str()
            .unwrap(),
        event.delta_ns as f64 / 1000000000.0,
        CStr::from_bytes_until_nul(&event.file)
            .unwrap()
            .to_str()
            .unwrap()
    );
    0
}

fn main() -> Result<()> {
    let opts = Command::parse();

    let mut open_object = MaybeUninit::uninit();
    let mut skel_builder = FilelifeSkelBuilder::default();
    if opts.verbose {
        skel_builder.object_builder_mut().debug(true);
    }

    let open_skel = skel_builder.open(&mut open_object)?;

    if let Some(pid) = opts.pid {
        open_skel.maps.rodata_data.targ_tgid = pid;
    }

    let mut skel = open_skel.load()?;
    skel.attach()?;

    let mut ringbuf_builder = RingBufferBuilder::new();
    ringbuf_builder.add(&skel.maps.events, handle_event)?;
    let ringbuf = ringbuf_builder.build()?;

    println!(
        "{:<8} {:<6} {:<16} {:<7} FILE",
        "TIME", "PID", "COMM", "AGE(s)"
    );

    loop {
        ringbuf.poll(Duration::MAX)?;
    }
}
