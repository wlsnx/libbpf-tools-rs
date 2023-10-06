use anyhow::{bail, Result};
use clap::Parser;
use libbpf_rs::{
    skel::{OpenSkel, Skel, SkelBuilder},
    PerfBufferBuilder,
};
use plain::Plain;

use std::ffi::CStr;
use std::time::Duration;

mod opensnoop {
    include!(concat!(env!("OUT_DIR"), "/opensnoop.skel.rs"));
}

use opensnoop::*;

unsafe impl Plain for opensnoop_rodata_types::event {}

#[derive(Parser, Debug)]
#[command(about = "Trace open family syscalls")]
struct Command {
    /// Duration to trace
    #[arg(short, long)]
    duration: Option<usize>,
    /// Print extended fields
    #[arg(short, long)]
    extended_fields: bool,
    /// Trace process names containing this
    #[arg(short, long)]
    name: Option<String>,
    /// Process ID to trace
    #[arg(short, long)]
    pid: Option<i32>,
    /// Thread ID to trace
    #[arg(short, long)]
    tid: Option<i32>,
    /// Print timestamp
    #[arg(short = 'T', long)]
    timestamp: bool,
    /// User ID to trace
    #[arg(short, long)]
    uid: Option<u32>,
    /// Print UID
    #[arg(short = 'U', long)]
    print_uid: bool,
    /// Verbose debug output
    #[arg(short, long)]
    verbose: bool,
    /// Failed opens only
    #[arg(short = 'x', long)]
    failed: bool,
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

fn handle_event(_cpu: i32, data: &[u8], opts: &Command) {
    let mut event = opensnoop_rodata_types::event::default();
    let mut data = data.to_vec();
    data.extend(vec![0; 7680]);
    plain::copy_from_bytes(&mut event, &data).expect("Data buffer was too short");

    if opts.timestamp {
        let now = chrono::Local::now();
        print!("{:<8} ", now);
    }
    if opts.print_uid {
        print!("{:<7} ", event.uid);
    }

    let comm = CStr::from_bytes_until_nul(&event.comm)
        .unwrap()
        .to_string_lossy();
    let fname = CStr::from_bytes_until_nul(&event.fname)
        .unwrap()
        .to_string_lossy();

    let fd;
    let err;
    if event.ret > 0 {
        fd = event.ret;
        err = 0;
    } else {
        fd = -1;
        err = -event.ret;
    }

    print!("{:<6} {:<16} {:3} {:3} ", event.pid, comm, fd, err);

    if opts.extended_fields {
        print!("{:08o} ", event.flags);
    }
    println!("{}", fname);
}

fn handle_lost_events(cpu: i32, count: u64) {
    eprintln!("Lost {count} events on CPU {cpu}");
}

fn main() -> Result<()> {
    let opts = Command::parse();

    let mut skel_builder = OpensnoopSkelBuilder::default();
    if opts.verbose {
        skel_builder.obj_builder.debug(true);
    }

    bump_memlock_rlimit()?;

    let mut open_skel = skel_builder.open()?;

    if let Some(pid) = opts.pid {
        open_skel.rodata().targ_tgid = pid;
    }
    if let Some(tid) = opts.tid {
        open_skel.rodata().targ_pid = tid;
    }
    if let Some(uid) = opts.uid {
        open_skel.rodata().targ_uid = uid;
    }
    if opts.failed {
        open_skel.rodata().targ_failed = opts.failed;
    }

    let mut skel = open_skel.load()?;

    skel.attach()?;

    let perf = PerfBufferBuilder::new(skel.maps_mut().events())
        .sample_cb(|cpu, data| handle_event(cpu, data, &opts))
        .lost_cb(handle_lost_events)
        .build()?;

    if opts.timestamp {
        print!("{:<8} ", "TIME");
    }
    if opts.print_uid {
        print!("{:<7}", "UID");
    }
    if opts.extended_fields {
        print!("{:<8} PATH ", "FLAGS");
    }

    loop {
        perf.poll(Duration::from_millis(100))?;
    }
}
