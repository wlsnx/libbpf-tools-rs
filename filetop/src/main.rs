#![feature(cstr_from_bytes_until_nul)]

use anyhow::{bail, Result};
use clap::Parser;
use libbpf_rs::{Map, MapFlags};
use plain::Plain;
use std::ffi::CStr;
use std::thread::sleep;
use std::time::Duration;
// use time::{macros::format_description, OffsetDateTime};

mod filetop {
    include!(concat!(env!("OUT_DIR"), "/filetop.skel.rs"));
}

use filetop::*;

unsafe impl Plain for filetop_bss_types::file_stat {}

#[derive(Parser, Debug)]
struct Command {
    #[arg(short)]
    pid: Option<i32>,
    #[arg(short = 'C')]
    noclear: bool,
    #[arg(short)]
    all: bool,
    #[arg(short, default_value = "all")]
    sort: String,
    #[arg(short, default_value = "20")]
    rows: u32,
    #[arg(short)]
    verbose: bool,
    #[arg(last = true, default_value = "1")]
    interval: u64,
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

fn print_stat(map: &mut Map) -> Result<()> {
    println!(
        "{:<7} {:<16} {:<6} {:<6} {:<7} {:<7} {:<1} {}",
        "TID", "COMM", "READS", "WRITES", "R_KB", "W_KB", "T", "FILE"
    );
    let keys: Vec<_> = map.keys().collect();
    for key in keys {
        let value = map.lookup(&key, MapFlags::ANY)?.unwrap();
        map.delete(&key)?;

        let mut file_stat = filetop_bss_types::file_stat::default();
        file_stat
            .copy_from_bytes(&value)
            .expect("Data buffer was too short");
        println!(
            "{:<7} {:<16} {:<6} {:<6} {:<7} {:<7} {:<1} {}",
            file_stat.tid,
            CStr::from_bytes_until_nul(&file_stat.comm)?.to_str()?,
            file_stat.reads,
            file_stat.writes,
            file_stat.read_bytes / 1024,
            file_stat.write_bytes / 1024,
            char::from_u32(file_stat._type as u32).unwrap(),
            CStr::from_bytes_until_nul(&file_stat.filename)?.to_str()?,
        );
    }
    Ok(())
}

fn main() -> Result<()> {
    let opts = Command::parse();

    let mut skel_builder = FiletopSkelBuilder::default();
    if opts.verbose {
        skel_builder.obj_builder.debug(true);
    }

    bump_memlock_rlimit()?;

    let mut open_skel = skel_builder.open()?;

    if let Some(pid) = opts.pid {
        open_skel.rodata().target_pid = pid;
    }
    open_skel.rodata().regular_file_only = !opts.all;

    let mut skel = open_skel.load()?;

    skel.attach()?;

    loop {
        sleep(Duration::from_secs(opts.interval));
        if !opts.noclear {
            print!("\x1B[2J\x1B[1;1H");
        }
        print_stat(skel.maps_mut().entries())?;
    }
}