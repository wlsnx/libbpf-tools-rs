use std::{
    borrow::BorrowMut,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::fd::{AsFd, AsRawFd},
    time::Duration,
};

use anyhow::{bail, Result};
use clap::Parser;
use libbpf_rs::{MapFlags, PerfBufferBuilder};
use plain::Plain;
use time::{macros::format_description, OffsetDateTime};

mod bindsnoop {
    include!(concat!(env!("OUT_DIR"), "/bindsnoop.skel.rs"));
}

use bindsnoop::*;

unsafe impl Plain for bindsnoop_rodata_types::bind_event {}

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

const IPPROTO_TCP: u16 = 6;
const IPPROTO_UDP: u16 = 17;

#[derive(Parser, Debug)]
struct Command {
    #[arg(short, long)]
    timestamp: bool,
    #[arg(short, long)]
    cgroup: Option<String>,
    #[arg(short = 'x', long)]
    failed: bool,
    #[arg(short, long)]
    pid: Option<u32>,
    #[arg(short = 'P', long)]
    ports: Option<String>,
    #[arg(short, long)]
    verbose: bool,
}

fn handle_event(_cpu: i32, data: &[u8], emit_timestamp: bool) {
    let mut event = bindsnoop_rodata_types::bind_event::default();
    plain::copy_from_bytes(&mut event, data).expect("Data buffer was too short");

    if emit_timestamp {
        let now = if let Ok(now) = OffsetDateTime::now_local() {
            let format = format_description!("[hour]:[minute]:[second]");
            now.format(&format)
                .unwrap_or_else(|_| "00:00:00".to_string())
        } else {
            "00:00:00".to_string()
        };
        print!("{:8} ", now);
    }

    let proto = match event.proto {
        IPPROTO_TCP => "TCP",
        IPPROTO_UDP => "UDP",
        _ => "UNK",
    };

    let mut opts = ['F', 'T', 'N', 'R', 'r'];
    for i in 0..5 {
        if ((1 << i) & event.opts) == 0 {
            opts[i] = '.';
        }
    }
    let opts: String = opts.iter().collect();

    let addr = match event.ver {
        4 => IpAddr::V4(Ipv4Addr::from(event.addr.to_be() as u32)),
        6 => IpAddr::V6(Ipv6Addr::from(event.addr.to_be())),
        _ => unreachable!(),
    };

    let task = std::str::from_utf8(&event.task).unwrap();

    println!(
        "{:<7} {:<16} {:<3} {:<5} {:<5} {:<4} {:<5} {:<48}",
        event.pid, task, event.ret, proto, opts, event.bound_dev_if, event.port, addr
    );
}

fn handle_lost_events(cpu: i32, lost_cnt: u64) {
    println!("lost {} events on CPU #{}", lost_cnt, cpu);
}

fn main() -> Result<()> {
    let opts = Command::parse();

    let mut skel_builder = BindsnoopSkelBuilder::default();
    if opts.verbose {
        skel_builder.obj_builder.debug(true);
    }

    bump_memlock_rlimit()?;

    let mut open_skel = skel_builder.open()?;

    if opts.cgroup.is_some() {
        open_skel.rodata().filter_cg = true;
    }
    open_skel.rodata().target_pid = opts.pid.unwrap_or(0) as i32;
    open_skel.rodata().ignore_errors = !opts.failed;
    open_skel.rodata().filter_by_port = opts.ports.is_some();

    let mut skel = open_skel.load()?;

    if let Some(cgroupspath) = opts.cgroup {
        let cgfd = std::fs::File::open(cgroupspath)?;
        skel.maps_mut().cgroup_map().update(
            &[0; 4],
            &cgfd.as_raw_fd().to_ne_bytes(),
            MapFlags::ANY,
        )?;
    }

    if let Some(ports) = opts.ports {
        for port in ports.split(",") {
            let port_num: u16 = port.parse()?;
            skel.maps_mut().ports().update(
                &port_num.to_ne_bytes(),
                &port_num.to_ne_bytes(),
                MapFlags::ANY,
            )?;
        }
    }

    skel.attach()?;

    let perf = PerfBufferBuilder::new(skel.maps_mut().events())
        .sample_cb(|cpu, data| handle_event(cpu, data, opts.timestamp))
        .lost_cb(handle_lost_events)
        .build()?;

    if opts.timestamp {
        print!("{:8} ", "TIME(s)");
    }

    println!(
        "{:<7} {:<16} {:<3} {:<5} {:<5} {:<4} {:<5} {:<48}",
        "PID", "COMM", "RET", "PROTO", "OPTS", "IF", "PORT", "ADDR"
    );

    loop {
        perf.poll(Duration::from_millis(100))?;
    }
}