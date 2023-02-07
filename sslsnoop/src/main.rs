#![feature(cstr_from_bytes_until_nul)]

use anyhow::{bail, Result};
use clap::Parser;
use hexyl::PrinterBuilder;
use libbpf_rs::{RingBufferBuilder, UprobeOpts};
use plain::Plain;
use std::ffi::CStr;
use std::io::{self, BufWriter};
use std::time::Duration;

mod sslsnoop {
    include!(concat!(env!("OUT_DIR"), "/sslsnoop.skel.rs"));
}

use sslsnoop::*;

unsafe impl Plain for sslsnoop_rodata_types::event {}

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

const DATA_MAX_LEN: usize = 4096;

fn handle_event(data: &[u8], len: usize) -> i32 {
    let mut data = data.to_vec();
    data.extend_from_slice(&[0; DATA_MAX_LEN]);
    let mut event = sslsnoop_rodata_types::event::default();
    event.copy_from_bytes(&data).unwrap();
    let data = &event.data[..(event.len as usize).min(DATA_MAX_LEN)];
    let comm = CStr::from_bytes_until_nul(&event.comm)
        .unwrap()
        .to_str()
        .unwrap();
    println!(
        "{} PID:{} TGID:{} COMMAND:{} {}:{}",
        chrono::Local::now().format("%H:%M:%S"),
        event.pid_tgid >> 32,
        event.pid_tgid & 0xffffffff,
        comm,
        if event.is_read { "READ" } else { "WRITE" },
        event.len,
    );
    let stdout = io::stdout();
    let mut stdout_lock = BufWriter::new(stdout.lock());
    let mut printer = PrinterBuilder::new(&mut stdout_lock)
        // .show_color(show_color)
        // .show_char_panel(show_char_panel)
        // .show_position_panel(show_position_panel)
        // .with_border_style(border_style)
        // .enable_squeezing(squeeze)
        // .num_panels(panels)
        // .group_size(group_size)
        // .with_base(base)
        .build();
    printer.print_all(&data[..len.min(data.len())]).unwrap();
    return 0;
}

#[derive(Parser)]
#[command(about = "Trace SSL Read and Write")]
struct Command {
    #[arg(short, long)]
    attach: Option<String>,
    /// Verbose debug output
    #[arg(short, long)]
    verbose: bool,
    #[arg(short, long)]
    len: Option<usize>,
}

fn main() -> Result<()> {
    let command = Command::parse();
    let mut skel_builder = SslsnoopSkelBuilder::default();
    if command.verbose {
        skel_builder.obj_builder.debug(true);
    }

    bump_memlock_rlimit()?;

    let open_skel = skel_builder.open()?;

    let mut skel = open_skel.load()?;

    // skel.attach()?;

    if let Some(attach) = &command.attach {
        let mut links = Vec::new();
        for attach_option in attach.split(",") {
            let mut split = attach_option.split(":");
            let path = split.next().unwrap();
            for func_name in split {
                let opts = UprobeOpts {
                    func_name: func_name.into(),
                    ..Default::default()
                };
                links.push(
                    skel.progs_mut()
                        .probe_func()
                        .attach_uprobe_with_opts(-1, path, 0, opts)?,
                );
                let opts = UprobeOpts {
                    func_name: func_name.into(),
                    retprobe: true,
                    ..Default::default()
                };
                links.push(if func_name.to_lowercase().contains("read") {
                    skel.progs_mut()
                        .retprobe_read()
                        .attach_uprobe_with_opts(-1, path, 0, opts)?
                } else {
                    skel.progs_mut()
                        .retprobe_write()
                        .attach_uprobe_with_opts(-1, path, 0, opts)?
                });
            }
        }

        let len = command.len.unwrap_or(DATA_MAX_LEN);
        let mut ringbuf_builder = RingBufferBuilder::new();
        ringbuf_builder.add(skel.maps().events(), |data| handle_event(data, len))?;
        let ringbuf = ringbuf_builder.build()?;

        loop {
            ringbuf.poll(Duration::from_millis(100))?;
        }
    }

    Ok(())
}
