use anyhow::{bail, Result};
use clap::Parser;
use libbpf_rs::{
    skel::{OpenSkel, Skel, SkelBuilder},
    RingBufferBuilder,
};
use plain::Plain;
use std::collections::HashMap;
use std::fs::{read_dir, read_link};
use std::ptr;
use std::time::Duration;

mod writesnoop {
    include!(concat!(env!("OUT_DIR"), "/writesnoop.skel.rs"));
}

use writesnoop::*;

unsafe impl Plain for writesnoop_bss_types::event {}

#[derive(Parser, Debug)]
#[command(about = "Trace write syscalls")]
struct Command {
    #[arg(short, long)]
    pid: Option<i32>,
    /// only print commands matching this name
    #[arg(short, long)]
    name: Option<String>,
    /// show path
    #[arg(short = 'P', long)]
    path: bool,
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

fn handle_event(data: &[u8], path: bool, fds: &mut HashMap<(i32, i32), String>) -> i32 {
    let mut event = writesnoop_bss_types::event::default();
    event.copy_from_bytes(data).unwrap();
    if path {
        if !fds.contains_key(&(event.pid, event.fd)) {
            for entry in read_dir(format!("/proc/{}/fd", event.pid)).unwrap() {
                let fd = entry.unwrap();
                fds.insert(
                    (
                        event.pid,
                        fd.path()
                            .file_name()
                            .unwrap()
                            .to_str()
                            .unwrap()
                            .parse()
                            .unwrap(),
                    ),
                    read_link(fd.path().to_str().unwrap())
                        .unwrap()
                        .to_string_lossy()
                        .to_string(),
                );
            }
        }
        let path = fds.get(&(event.pid, event.fd)).unwrap();
        println!("{}:", path);
    }
    print!(
        "{}",
        String::from_utf8_lossy(&event.data[..event.count as _])
    );
    0
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

    let mut fds = HashMap::new();
    let mut ringbuf_builder = RingBufferBuilder::new();
    let mut maps = skel.maps_mut();
    ringbuf_builder.add(maps.events(), |data| {
        handle_event(data, opts.path, &mut fds)
    })?;
    let ringbuf = ringbuf_builder.build()?;

    loop {
        ringbuf.poll(Duration::MAX)?;
    }
}
