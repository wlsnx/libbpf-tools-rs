use anyhow::{bail, Result};
use clap::Parser;
use libbpf_rs::RingBufferBuilder;
use std::ffi::CStr;
use std::ptr;
use std::time::Duration;

mod writesnoop {
    include!(concat!(env!("OUT_DIR"), "/writesnoop.skel.rs"));
}

use writesnoop::*;

#[derive(Parser, Debug)]
#[command(about = "Trace write syscalls")]
struct Command {
    #[arg(short, long)]
    pid: Option<i32>,
    /// only print commands matching this name
    #[arg(short, long)]
    name: Option<String>,
    /// Verbose debug output
    #[arg(short, long)]
    verbose: bool,
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

fn handle_event(data: &[u8]) -> i32 {
    let mut data = data.to_vec();
    data.push(0);
    print!(
        "{}",
        CStr::from_bytes_until_nul(&data).unwrap().to_string_lossy()
    );
    return 0;
}

fn main() -> Result<()> {
    let opts = Command::parse();

    let mut skel_builder = WritesnoopSkelBuilder::default();
    if opts.verbose {
        skel_builder.obj_builder.debug(true);
    }

    bump_memlock_rlimit()?;

    let mut open_skel = skel_builder.open()?;

    if let Some(pid) = opts.pid {
        open_skel.rodata().target_pid = pid;
    }

    if let Some(name) = opts.name {
        unsafe {
            ptr::copy(
                name.as_ptr(),
                open_skel.rodata().target_comm.as_mut_ptr(),
                name.len().min(255),
            );
        }
    }

    let mut skel = open_skel.load()?;
    skel.attach()?;

    let mut ringbuf_builder = RingBufferBuilder::new();
    ringbuf_builder.add(skel.maps_mut().events(), handle_event)?;
    let ringbuf = ringbuf_builder.build()?;

    loop {
        ringbuf.poll(Duration::MAX)?;
    }
}
