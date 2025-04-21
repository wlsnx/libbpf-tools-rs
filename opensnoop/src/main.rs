use anyhow::Result;
use clap::Parser;
use libbpf_rs::{
    skel::{OpenSkel, Skel, SkelBuilder},
    RingBufferBuilder,
};
use mio::{event::Source, unix::SourceFd};
use tokio::io::unix::AsyncFd;
use tokio_bpfmap::AsyncBuffer;

use std::time::Duration;
use std::{ffi::CStr, mem::MaybeUninit};

mod opensnoop {
    include!("bpf/opensnoop.skel.rs");
}

use opensnoop::*;

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

fn handle_event(data: &[u8], opts: &Command) -> i32 {
    let event: types::event = unsafe { *(data.as_ptr().cast()) };

    let comm = CStr::from_bytes_until_nul(&event.comm)
        .unwrap()
        .to_string_lossy();
    let fname = CStr::from_bytes_until_nul(&event.fname)
        .unwrap()
        .to_string_lossy();

    if opts.name.clone().is_some_and(|name| !comm.contains(&name)) {
        return 0;
    }

    if opts.timestamp {
        let now = chrono::Local::now();
        print!("{:<8} ", now);
    }
    if opts.print_uid {
        print!("{:<7} ", event.uid);
    }

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
    0
}

#[tokio::main]
async fn main() -> Result<()> {
    let opts = Command::parse();

    let mut skel_builder = OpensnoopSkelBuilder::default();
    if opts.verbose {
        skel_builder.object_builder_mut().debug(true);
    }

    let mut obj = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut obj)?;

    if let Some(pid) = opts.pid {
        open_skel.maps.rodata_data.targ_tgid = pid;
    }
    if let Some(tid) = opts.tid {
        open_skel.maps.rodata_data.targ_pid = tid;
    }
    if let Some(uid) = opts.uid {
        open_skel.maps.rodata_data.targ_uid = uid;
    }
    if opts.failed {
        open_skel.maps.rodata_data.targ_failed = opts.failed;
    }

    let mut skel = open_skel.load()?;

    skel.attach()?;

    let mut ringbuf_builder = RingBufferBuilder::new();
    ringbuf_builder.add(&skel.maps.events, |data| handle_event(data, &opts))?;
    let ringbuf = ringbuf_builder.build()?;

    if opts.timestamp {
        print!("{:<8} ", "TIME");
    }
    if opts.print_uid {
        print!("{:<7}", "UID");
    }
    if opts.extended_fields {
        print!("{:<8} PATH ", "FLAGS");
    }

    let asyncbuf = AsyncBuffer::new(ringbuf)?;
    // let fd = ringbuf.epoll_fd();
    // let async_fd = AsyncFd::new(fd)?;
    loop {
        asyncbuf.readable().await?;
        asyncbuf.poll(Duration::MAX)?;
    }
}
