use anyhow::Result;
use clap::Parser;
use libbpf_rs::{
    skel::{OpenSkel, Skel, SkelBuilder},
    RingBufferBuilder,
};
use std::fs::{read_dir, read_link};
use std::ptr;
use std::time::Duration;
use std::{collections::HashMap, mem::MaybeUninit};
use types::event;

mod writesnoop {
    include!("bpf/writesnoop.skel.rs");
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
    /// show path
    #[arg(short = 'P', long)]
    path: bool,
    /// Verbose debug output
    #[arg(short, long)]
    verbose: bool,
}

fn handle_event(data: &[u8], path: bool, fds: &mut HashMap<(i32, i32), String>) -> i32 {
    let event = unsafe { *(data.as_ptr().cast::<event>()) };
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
        skel_builder.object_builder_mut().debug(true);
    }

    let mut obj = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut obj)?;

    if let Some(pid) = opts.pid {
        open_skel.maps.rodata_data.target_pid = pid;
    }

    if let Some(name) = opts.name {
        unsafe {
            ptr::copy(
                name.as_ptr(),
                open_skel.maps.rodata_data.target_comm.as_mut_ptr(),
                name.len().min(255),
            );
        }
    }

    let mut skel = open_skel.load()?;
    skel.attach()?;

    let mut fds = HashMap::new();
    let mut ringbuf_builder = RingBufferBuilder::new();
    ringbuf_builder.add(&skel.maps.events, |data| {
        handle_event(data, opts.path, &mut fds)
    })?;
    let ringbuf = ringbuf_builder.build()?;

    loop {
        ringbuf.poll(Duration::MAX)?;
    }
}
