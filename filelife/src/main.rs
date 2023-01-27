#![feature(cstr_from_bytes_until_nul)]

use anyhow::{bail, Result};
use clap::Parser;
use libbpf_rs::PerfBufferBuilder;
use plain::Plain;
use std::{ffi::CStr, time::Duration};

mod filelife {
    include!(concat!(env!("OUT_DIR"), "/filelife.skel.rs"));
}

use filelife::*;

unsafe impl Plain for filelife_bss_types::event {}

#[derive(Debug, Parser)]
#[command(about = "Trace the lifespan of short-lived files.")]
struct Command {
    /// Verbose debug output
    #[arg(short)]
    verbose: bool,
    /// Process PID to trace
    #[arg(short)]
    pid: Option<i32>,
}

fn bump_memlock_rlimit() -> Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        bail!("Failed to increase rlimit");
    }

    Ok(())
}

fn handle_event(_cpu: i32, data: &[u8]) {
    let mut event = filelife_bss_types::event::default();
    plain::copy_from_bytes(&mut event, data).expect("Data buffer was too short");

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
    )
}

fn handle_lost_events(cpu: i32, count: u64) {
    eprintln!("Lost {} events on CPU {}", count, cpu);
}

fn main() -> Result<()> {
    let opts = Command::parse();

    let mut skel_builder = FilelifeSkelBuilder::default();
    if opts.verbose {
        skel_builder.obj_builder.debug(true);
    }

    bump_memlock_rlimit()?;

    let mut open_skel = skel_builder.open()?;

    if let Some(pid) = opts.pid {
        open_skel.rodata().targ_tgid = pid;
    }

    let mut skel = open_skel.load()?;

    skel.attach()?;

    let perf = PerfBufferBuilder::new(skel.maps_mut().events())
        .sample_cb(handle_event)
        .lost_cb(handle_lost_events)
        .build()?;

    println!(
        "{:<8} {:<6} {:<16} {:<7} {}",
        "TIME", "PID", "COMM", "AGE(s)", "FILE"
    );

    loop {
        perf.poll(Duration::from_millis(100))?;
    }
}
