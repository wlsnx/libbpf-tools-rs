use anyhow::Result;
use clap::Parser;
use libbpf_rs::{
    skel::{OpenSkel, Skel, SkelBuilder},
    MapCore, MapFlags, PerfBufferBuilder,
};
use libc::{AF_INET, AF_INET6};
use phf::{phf_map, Map};
use std::{
    ffi::CStr,
    mem::MaybeUninit,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};

mod tcpstates {
    include!("bpf/tcpstates.skel.rs");
}

use tcpstates::*;

static TCP_STATES: Map<i32, &'static str> = phf_map! {
    1i32 => "ESTABLISHED",
    2i32 => "SYN_SENT",
    3i32 => "SYN_RECV",
    4i32 => "FIN_WAIT1",
    5i32 => "FIN_WAIT2",
    6i32 => "TIME_WAIT",
    7i32 => "CLOSE",
    8i32 => "CLOSE_WAIT",
    9i32 => "LAST_ACK",
    10i32 => "LISTEN",
    11i32 => "CLOSING",
    12i32 => "NEW_SYN_RECV",
    13i32 => "UNKNOWN",
};

#[derive(Debug, Parser)]
#[command(about = "Trace TCP session stat changes and durations.")]
struct Command {
    /// Verbose debug output
    #[arg(short)]
    verbose: bool,
    /// Include timestamp on output
    #[arg(short = 'T')]
    timestamp: bool,
    /// Trace IPv4 family only
    #[arg(short = '4')]
    ipv4: bool,
    /// Trace IPv6 family only
    #[arg(short = '6')]
    ipv6: bool,
    /// Wide column output (fits IPv6 addresses)
    #[arg(short)]
    wide: bool,
    /// Comma-separated list of local ports to trace.
    #[arg(short = 'S', long = "SPORT")]
    sport: Option<String>,
    /// Comma-separated list of remote ports to trace.
    #[arg(short = 'D', long = "DPORT")]
    dport: Option<String>,
}

fn to_str(data: &[u8]) -> &str {
    CStr::from_bytes_until_nul(data).unwrap().to_str().unwrap()
}

fn handle_event(_cpu: i32, data: &[u8], emit_timestamp: bool, ip_len: usize) {
    use types::event;
    // 检查数据长度是否足够
    assert!(
        data.len() >= std::mem::size_of::<event>(),
        "Data buffer too short"
    );
    // 强制类型转换
    let event = unsafe { &*(data.as_ptr() as *const event) };

    if emit_timestamp {
        let now = chrono::Local::now().format("%H:%M:%S");
        print!("{now:<8} ");
    }
    let saddr;
    let daddr;
    if event.family == AF_INET as _ {
        saddr = IpAddr::V4(Ipv4Addr::from((event.saddr as u32).to_be()));
        daddr = IpAddr::V4(Ipv4Addr::from((event.daddr as u32).to_be()));
    } else {
        saddr = IpAddr::V6(Ipv6Addr::from(event.saddr.to_be()));
        daddr = IpAddr::V6(Ipv6Addr::from(event.daddr.to_be()));
    }

    println!(
        "{:<16x} {:<7} {:<16} {:<ip_len$} {:<5} {:<ip_len$} {:<5} {:<11} -> {:<12} {:.3}",
        event.skaddr,
        event.pid,
        to_str(&event.task),
        saddr,
        event.sport,
        daddr,
        event.dport,
        TCP_STATES[&event.oldstate],
        TCP_STATES[&event.newstate],
        event.delta_us as f64 / 1000.0,
    );
}

fn handle_lost_events(cpu: i32, count: u64) {
    eprintln!("Lost {count} events on CPU {cpu}");
}

fn main() -> Result<()> {
    let opts = Command::parse();

    let mut skel_builder = TcpstatesSkelBuilder::default();
    if opts.verbose {
        skel_builder.obj_builder.debug(true);
    }

    let mut obj = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut obj)?;

    if opts.sport.is_some() {
        open_skel.maps.rodata_data.filter_by_sport = true;
    }

    if opts.dport.is_some() {
        open_skel.maps.rodata_data.filter_by_dport = true;
    }

    if opts.ipv4 || opts.ipv6 {
        if !opts.ipv4 {
            open_skel.maps.rodata_data.target_family = AF_INET6 as _;
        } else {
            open_skel.maps.rodata_data.target_family = AF_INET as _;
        }
    }

    let mut skel = open_skel.load()?;

    if let Some(sport) = opts.sport {
        for port in sport.split(',') {
            let port_num = port.parse::<u16>()?;
            skel.maps.sports.update(
                &port_num.to_ne_bytes(),
                &port_num.to_ne_bytes(),
                MapFlags::ANY,
            )?;
        }
    }

    if let Some(dport) = opts.dport {
        for port in dport.split(',') {
            let port_num = port.parse::<u16>()?;
            skel.maps.dports.update(
                &port_num.to_ne_bytes(),
                &port_num.to_ne_bytes(),
                MapFlags::ANY,
            )?;
        }
    }

    skel.attach()?;

    let ip_len = if opts.wide || opts.ipv6 { 39 } else { 15 };
    let perf = PerfBufferBuilder::new(&skel.maps.events)
        .sample_cb(|cpu, data| handle_event(cpu, data, opts.timestamp, ip_len))
        .lost_cb(handle_lost_events)
        .build()?;

    if opts.timestamp {
        print!("{:<8} ", "TIME(s)");
    }

    println!(
        "{:<16} {:<7} {:<16} {:<ip_len$} {:<5} {:<ip_len$} {:<5} {:<11} -> {:<12} {:.3}",
        "SKADDR", "PID", "COMM", "LADDR", "LPORT", "RADDR", "RPORT", "OLDSTATE", "NEWSTATE", "MS"
    );

    loop {
        perf.poll(Duration::MAX)?;
    }
}
