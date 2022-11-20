use anyhow::{bail, Result};
use clap::Parser;
use libbpf_rs::PerfBufferBuilder;
use plain::Plain;
use std::time::Duration;
use time::{macros::format_description, OffsetDateTime};

mod bashreadline {
    include!(concat!(env!("OUT_DIR"), "/bashreadline.skel.rs"));
}

use bashreadline::*;

#[derive(Debug, Parser)]
struct Command {
    #[arg(short, long)]
    shared: Option<String>,
    #[arg(short, long, default_value_t)]
    verbose: bool,
}

unsafe impl Plain for bashreadline_bss_types::str_t {}

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
    let mut event = bashreadline_bss_types::str_t::default();
    plain::copy_from_bytes(&mut event, data).expect("Data buffer was too short");

    let now = if let Ok(now) = OffsetDateTime::now_local() {
        let format = format_description!("[hour]:[minute]:[second]");
        now.format(&format)
            .unwrap_or_else(|_| "00:00:00".to_string())
    } else {
        "00:00:00".to_string()
    };

    let index = event
        .str
        .iter()
        .enumerate()
        .find(|(_, &c)| c == 0)
        .unwrap()
        .0;
    let task = std::str::from_utf8(&event.str[..index]).unwrap();

    println!("{:-9} {:-7} {}", now, event.pid, task)
}

fn handle_lost_events(cpu: i32, count: u64) {
    eprintln!("Lost {} events on CPU {}", count, cpu);
}

fn find_readline_so() -> String {
    let bash_path = "/bin/bash";
    return bash_path.to_string();
}

fn main() -> Result<()> {
    let opts = Command::parse();

    let mut skel_builder = BashreadlineSkelBuilder::default();
    if opts.verbose {
        skel_builder.obj_builder.debug(true);
    }

    bump_memlock_rlimit()?;
    let open_skel = skel_builder.open()?;

    let mut skel = open_skel.load()?;

    let _link =
        skel.progs_mut()
            .printret()
            .attach_uprobe(true, -1, "/lib64/libreadline.so.8", 107312)?;
    // skel.attach()?;

    let perf = PerfBufferBuilder::new(skel.maps_mut().events())
        .pages(16)
        .sample_cb(handle_event)
        .lost_cb(handle_lost_events)
        .build()?;

    loop {
        perf.poll(Duration::from_millis(100))?;
    }
}
