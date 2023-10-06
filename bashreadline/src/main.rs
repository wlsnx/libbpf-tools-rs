use anyhow::{bail, Result};
use clap::Parser;
use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder},
    PerfBufferBuilder, UprobeOpts,
};
use plain::Plain;
use regex::Regex;
use std::time::Duration;

mod bashreadline {
    include!(concat!(env!("OUT_DIR"), "/bashreadline.skel.rs"));
}

use bashreadline::*;

#[derive(Debug, Parser)]
#[command(about = "Print entered bash commands from all running shells.")]
struct Command {
    /// the location of libreadline.so library
    #[arg(short, long)]
    shared: Option<String>,
    /// Verbose debug output
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

    let now = chrono::Local::now().format("%H:%M:%S");

    let index = event.str.iter().position(|&c| c == 0).unwrap();
    let task = std::str::from_utf8(&event.str[..index]).unwrap();

    println!("{:<9} {:<7} {}", now, event.pid, task)
}

fn handle_lost_events(cpu: i32, count: u64) {
    eprintln!("Lost {count} events on CPU {cpu}");
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

    let opts = UprobeOpts {
        retprobe: true,
        func_name: "readline".into(),
        ..Default::default()
    };
    let ldd = std::process::Command::new("ldd")
        .arg("/bin/bash")
        .output()?;
    let output = std::str::from_utf8(&ldd.stdout)?;
    let pattern = Regex::new(r"readline\.so[^ ]* => ([^ ]+)")?;
    let _link = if let Some(capture) = pattern.captures(output) {
        let readline_path = capture.get(1).unwrap().as_str();
        skel.progs_mut()
            .printret()
            .attach_uprobe_with_opts(-1, readline_path, 0, opts)?
    } else {
        skel.progs_mut()
            .printret()
            .attach_uprobe_with_opts(-1, "/bin/bash", 0, opts)?
    };

    let perf = PerfBufferBuilder::new(skel.maps_mut().events())
        .sample_cb(handle_event)
        .lost_cb(handle_lost_events)
        .build()?;

    println!("{:<9} {:<7} COMMAND", "TIME", "PID");

    loop {
        perf.poll(Duration::from_millis(100))?;
    }
}
