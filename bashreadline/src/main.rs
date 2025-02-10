use anyhow::{bail, Result};
use clap::Parser;
use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder},
    PerfBufferBuilder, UprobeOpts,
};
use regex::Regex;
use std::mem::MaybeUninit;
use std::time::Duration;

mod bashreadline {
    include!("bpf/bashreadline.skel.rs");
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
    let event: types::str_t = unsafe { *(data.as_ptr().cast()) };

    let now = chrono::Local::now().format("%H:%M:%S");

    let index = event.str.iter().position(|&c| c == 0).unwrap();
    let task = std::str::from_utf8(&event.str[..index]).unwrap();

    println!("{:<9} {:<7} {}", now, event.pid, task)
}

fn handle_lost_events(cpu: i32, count: u64) {
    eprintln!("Lost {count} events on CPU {cpu}");
}

fn find_readline_path() -> Result<String> {
    // 使用std::process::Command来查找readline路径
    let ldd = std::process::Command::new("ldd")
        .arg("/bin/bash")
        .output()?;
    let output = std::str::from_utf8(&ldd.stdout)?;
    let pattern = Regex::new(r"readline\.so[^ ]* => ([^ ]+)")?;
    if let Some(capture) = pattern.captures(output) {
        Ok(capture.get(1).unwrap().as_str().to_string())
    } else {
        bail!("Failed to find readline.so")
    }
}

fn main() -> Result<()> {
    let opts = Command::parse();

    let mut skel_builder = BashreadlineSkelBuilder::default();
    if opts.verbose {
        skel_builder.obj_builder.debug(true);
    }

    bump_memlock_rlimit()?;

    let mut open_skel = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_skel)?;

    let skel = open_skel.load()?;

    let opts = UprobeOpts {
        retprobe: true,
        func_name: "readline".into(),
        ..Default::default()
    };
    let readline_path = find_readline_path()?;
    let _link = skel
        .progs
        .printret
        .attach_uprobe_with_opts(-1, &readline_path, 0, opts)?;

    let perf = PerfBufferBuilder::new(&skel.maps.events)
        .sample_cb(handle_event)
        .lost_cb(handle_lost_events)
        .build()?;

    println!("{:<9} {:<7} COMMAND", "TIME", "PID");

    loop {
        perf.poll(Duration::from_millis(100))?;
    }
}
