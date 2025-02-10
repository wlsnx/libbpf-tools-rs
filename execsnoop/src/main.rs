use anyhow::Result;
use clap::Parser;
use libbpf_rs::{
    skel::{OpenSkel, Skel, SkelBuilder},
    MapCore, MapFlags, RingBufferBuilder,
};
use regex::Regex;

use std::os::fd::AsRawFd;
use std::time::Duration;
use std::{ffi::CStr, time::SystemTime};
use std::{fs::File, mem::MaybeUninit};

mod execsnoop {
    include!("bpf/execsnoop.skel.rs");
}

use execsnoop::*;

#[derive(Parser, Debug)]
#[command(about = "Trace exec syscalls")]
struct Command {
    /// include time column on output (HH:MM:SS)
    #[arg(short = 'T', long)]
    time: bool,
    /// include timestamp on output
    #[arg(short, long)]
    timestamp: bool,
    /// include failed exec()s
    #[arg(short = 'x', long)]
    fails: bool,
    /// trace this UID only
    #[arg(short, long)]
    uid: Option<u32>,
    /// Add quotemarks (") around arguments
    #[arg(short, long)]
    quote: bool,
    /// only print commands matching this name, any arg
    #[arg(short, long)]
    name: Option<String>,
    /// only print commands where arg contains this line
    #[arg(short, long)]
    line: Option<String>,
    /// print UID column
    #[arg(short = 'U', long)]
    print_uid: bool,
    /// maximun number of arguments parsed and displayed
    #[arg(long, default_value = "60")]
    max_args: i32,
    /// Verbose debug output
    #[arg(short, long)]
    verbose: bool,
    /// Trace process in cgroup path
    #[arg(short, long, value_name = "PATH")]
    cgroup: Option<String>,
}

fn handle_event(
    data: &[u8],
    opts: &Command,
    start_time: &SystemTime,
    name_regex: &Option<Regex>,
    line_regex: &Option<Regex>,
) {
    let event: types::event = unsafe { *data.as_ptr().cast() };

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

    let now = chrono::Local::now().format("%H:%M:%S");

    if opts.time {
        print!("{now:<8} ");
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

    println!("{:<16} {:<6} {:<6} {}", comm, event.pid, event.ppid, args,);
}

fn join_args(event: types::event, opts: &Command) -> String {
    let args: Vec<_> = event
        .args
        .split(|&c| c == 0)
        .take(event.args_count as usize)
        .map(|arg| {
            let str = std::str::from_utf8(arg).unwrap();
            let len = str.len();
            let str = str.escape_debug().to_string();
            if str.contains(' ') || str.len() != len {
                format!("\"{str}\"")
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

fn main() -> Result<()> {
    let start_time = SystemTime::now();
    let opts = Command::parse();

    let mut skel_builder = ExecsnoopSkelBuilder::default();
    if opts.verbose {
        skel_builder.object_builder_mut().debug(true);
    }

    let mut obj = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut obj)?;

    open_skel.maps.rodata_data.ignore_failed = !opts.fails;
    if let Some(uid) = opts.uid {
        open_skel.maps.rodata_data.targ_uid = uid;
    }
    open_skel.maps.rodata_data.max_args = opts.max_args;

    if opts.cgroup.is_some() {
        open_skel.maps.rodata_data.filter_cg = true;
    }

    let mut skel = open_skel.load()?;

    if let Some(ref cgroupspath) = opts.cgroup {
        let cgfd = File::open(cgroupspath)?;
        skel.maps
            .cgroup_map
            .update(&[0; 4], &cgfd.as_raw_fd().to_ne_bytes(), MapFlags::ANY)?;
    }

    skel.attach()?;

    let name_regex = opts.name.as_ref().map(|name| Regex::new(name).unwrap());
    let line_regex = opts.line.as_ref().map(|line| Regex::new(line).unwrap());

    let mut builder = RingBufferBuilder::new();
    builder.add(&skel.maps.events, |data| {
        handle_event(data, &opts, &start_time, &name_regex, &line_regex);
        0
    })?;
    let ringbuf = builder.build()?;

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
        "{:<16} {:<6} {:<6} {:3} ARGS",
        "PCOMM", "PID", "PPID", "RET"
    );
    loop {
        ringbuf.poll(Duration::MAX)?;
    }
}
