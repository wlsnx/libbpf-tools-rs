#![feature(cstr_from_bytes_until_nul)]

use anyhow::{bail, Result};
use clap::Parser;
use libbpf_rs::PerfBufferBuilder;
use plain::Plain;
use regex::Regex;

use std::time::Duration;
use std::{ffi::CStr, time::SystemTime};
use time::{macros::format_description, OffsetDateTime};

mod execsnoop {
    include!(concat!(env!("OUT_DIR"), "/execsnoop.skel.rs"));
}

use execsnoop::*;

unsafe impl Plain for execsnoop_rodata_types::event {}

#[derive(Parser, Debug)]
#[command(about = "Trace exec syscalls")]
struct Command {
    /// include time column on output (HH:MM:SS)
    #[arg(short = 'T')]
    time: bool,
    /// include timestamp on output
    #[arg(short = 't')]
    timestamp: bool,
    /// include failed exec()s
    #[arg(short)]
    fails: bool,
    /// trace this UID only
    #[arg(short)]
    uid: Option<u32>,
    /// Add quotemarks (") around arguments
    #[arg(short)]
    quote: bool,
    /// only print commands matching this name, any arg
    #[arg(short)]
    name: Option<String>,
    /// only print commands where arg contains this line
    #[arg(short)]
    line: Option<String>,
    /// print UID column
    #[arg(short = 'U')]
    print_uid: bool,
    /// maximun number of arguments parsed and displayed
    #[arg(long, default_value = "20")]
    max_args: i32,
    /// Verbose debug output
    #[arg(short)]
    verbose: bool,
    /// Trace process in cgroup path
    #[arg(short)]
    cgroup: bool,
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

fn handle_event(
    _cpu: i32,
    data: &[u8],
    opts: &Command,
    start_time: &SystemTime,
    name_regex: &Option<Regex>,
    line_regex: &Option<Regex>,
) {
    let mut event = execsnoop_rodata_types::event::default();
    let mut data = data.to_vec();
    data.extend(vec![0; 7680]);
    plain::copy_from_bytes(&mut event, &data).expect("Data buffer was too short");

    let comm = CStr::from_bytes_until_nul(&event.comm)
        .unwrap()
        .to_str()
        .unwrap();
    if let Some(regex) = name_regex {
        if !regex.is_match(comm) {
            return;
        }
    }

    let args = join_args(event, opts);
    if let Some(regex) = line_regex {
        if !regex.is_match(&args) {
            return;
        }
    }

    let now = if let Ok(now) = OffsetDateTime::now_local() {
        let format = format_description!("[hour]:[minute]:[second]");
        now.format(&format)
            .unwrap_or_else(|_| "00:00:00".to_string())
    } else {
        "00:00:00".to_string()
    };

    if opts.time {
        print!("{:<8} ", now);
    }

    if opts.timestamp {
        print!(
            "{:<8.3} ",
            start_time.elapsed().unwrap().as_millis() as f64 / 1000.0
        )
    }

    if opts.print_uid {
        print!("{:<6} ", event.uid);
    }

    println!(
        "{:<16} {:<6} {:<6} {:3} {}",
        comm, event.pid, event.ppid, event.retval, args,
    );
}

fn join_args(event: execsnoop_rodata_types::event, opts: &Command) -> String {
    let args: Vec<_> = event
        .args
        .split(|&c| c == 0)
        .take(event.args_count as usize)
        .map(|arg| {
            let str = std::str::from_utf8(arg).unwrap();
            let len = str.len();
            let str = str.escape_debug().to_string();
            if str.contains(" ") || str.len() != len {
                format!("\"{}\"", str)
            } else {
                str
            }
        })
        .collect();
    let mut args_str = args.join(" ");

    if event.args_count == opts.max_args + 1 {
        args_str.push_str(" ...");
    }
    args_str
}

fn handle_lost_events(cpu: i32, count: u64) {
    eprintln!("Lost {} events on CPU {}", count, cpu);
}

fn main() -> Result<()> {
    let start_time = SystemTime::now();
    let opts = Command::parse();

    let mut skel_builder = ExecsnoopSkelBuilder::default();
    if opts.verbose {
        skel_builder.obj_builder.debug(true);
    }

    bump_memlock_rlimit()?;

    let mut open_skel = skel_builder.open()?;

    open_skel.rodata().ignore_failed = !opts.fails;
    if let Some(uid) = opts.uid {
        open_skel.rodata().targ_uid = uid;
    }
    open_skel.rodata().max_args = opts.max_args;
    open_skel.rodata().filter_cg = opts.cgroup;

    let mut skel = open_skel.load()?;

    skel.attach()?;

    let name_regex = opts.name.as_ref().map(|name| Regex::new(name).unwrap());
    let line_regex = opts.line.as_ref().map(|line| Regex::new(line).unwrap());

    let perf = PerfBufferBuilder::new(skel.maps_mut().events())
        .sample_cb(|cpu, data| {
            handle_event(cpu, data, &opts, &start_time, &name_regex, &line_regex)
        })
        .lost_cb(handle_lost_events)
        .build()?;

    if opts.time {
        print!("{:<8} ", "TIME");
    }
    if opts.timestamp {
        print!("{:<8} ", "TIME(s)");
    }
    if opts.print_uid {
        print!("{:<6} ", "UID");
    }

    println!(
        "{:<16} {:<6} {:<6} {:3} {}",
        "PCOMM", "PID", "PPID", "RET", "ARGS"
    );
    loop {
        perf.poll(Duration::from_millis(100))?;
    }
}
