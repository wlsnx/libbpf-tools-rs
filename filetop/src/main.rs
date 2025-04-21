use anyhow::{bail, Result};
use clap::Parser;
use libbpf_rs::{
    skel::{OpenSkel, Skel, SkelBuilder},
    Map, MapCore, MapFlags,
};
use std::ffi::CStr;
use std::mem::MaybeUninit;
use std::thread::sleep;
use std::time::Duration;

mod filetop {
    include!("bpf/filetop.skel.rs");
}

use filetop::*;

#[derive(Parser, Debug)]
#[command(about = "Trace file reads/writes by process.")]
struct Command {
    /// Process ID to trace
    #[arg(short)]
    pid: Option<i32>,
    /// Don't clear the screen
    #[arg(short = 'C')]
    noclear: bool,
    /// Include special files
    #[arg(short)]
    all: bool,
    /// Sort columns (all, reads, writes, rbytes, wbytes)
    #[arg(short, default_value = "all", value_parser = ["all", "reads", "writes", "rbytes", "wbytes"])]
    sort: String,
    /// Maximum rows to print
    #[arg(short, default_value = "20")]
    rows: u32,
    /// Verbose debug output
    #[arg(short)]
    verbose: bool,
    #[arg(default_value = "1")]
    interval: u64,
    #[arg(short)]
    count: Option<u64>,
}

fn print_stat(map: &Map, rows: u32, sort: &str) -> Result<()> {
    println!(
        "{:<7} {:<16} {:<6} {:<6} {:<7} {:<7} {:<1} FILE",
        "TID", "COMM", "READS", "WRITES", "R_KB", "W_KB", "T"
    );

    let keys: Vec<_> = map.keys().collect();
    let mut values: Vec<_> = keys
        .iter()
        .filter_map(|k| map.lookup_and_delete(&k).ok()?)
        .map(|v| unsafe { *(v.as_ptr() as *const types::file_stat) })
        .collect();
    let sort_key_fn: fn(&types::file_stat) -> (u64, u64, u64, u64) = match sort {
        "all" => |v| (v.reads, v.writes, v.read_bytes, v.write_bytes),
        "reads" => |v| (v.reads, 0, 0, 0),
        "writes" => |v| (v.writes, 0, 0, 0),
        "rbytes" => |v| (v.read_bytes, 0, 0, 0),
        "wbytes" => |v| (v.write_bytes, 0, 0, 0),
        _ => unreachable!(),
    };
    values.sort_by_key(sort_key_fn);
    values.reverse();
    for file_stat in values.iter().take(rows as _) {
        let filename = CStr::from_bytes_until_nul(&file_stat.filename)?.to_str()?;
        // 反转文件名
        let mut components: Vec<_> = filename.split("/").collect();
        components.reverse();
        let rev_filename = components.join("/");

        println!(
            "{:<7} {:<16} {:<6} {:<6} {:<7} {:<7} {:<1} {}",
            file_stat.tid,
            CStr::from_bytes_until_nul(&file_stat.comm)?.to_str()?,
            file_stat.reads,
            file_stat.writes,
            file_stat.read_bytes / 1024,
            file_stat.write_bytes / 1024,
            char::from_u32(file_stat._type as u32).unwrap(),
            rev_filename,
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

    let mut open_obj = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_obj)?;

    if let Some(pid) = opts.pid {
        open_skel.maps.rodata_data.target_pid = pid;
    }
    open_skel.maps.rodata_data.regular_file_only = !opts.all;

    let mut skel = open_skel.load()?;
    skel.attach()?;

    let mut count = opts.count;
    loop {
        sleep(Duration::from_secs(opts.interval));
        if !opts.noclear {
            print!("\x1B[2J\x1B[1;1H");
        }
        print_stat(&skel.maps.entries, opts.rows, &opts.sort)?;
        match count {
            Some(0) => break,
            Some(c) => {
                let _ = count.insert(c - 1);
            }
            None => (),
        }
    }
    Ok(())
}
