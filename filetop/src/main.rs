use anyhow::Result;
use clap::Parser;
use libbpf_rs::{
    skel::{OpenSkel, Skel, SkelBuilder},
    Map,
    MapCore, // Added MapCore trait
    MapFlags,
};
use std::ffi::CStr;
use std::mem::MaybeUninit;
use std::thread::sleep;
use std::time::Duration; // Added for open() method

mod filetop {
    include!("bpf/filetop.skel.rs");
}

use filetop::*; // Add this to access bss types

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
    #[arg(short, default_value = "all")]
    sort: String,
    /// Maximum rows to print
    #[arg(short, default_value = "20")]
    rows: u32,
    /// Verbose debug output
    #[arg(short)]
    verbose: bool,
    #[arg(default_value = "3")]
    interval: u64,
    #[arg(default_value = "99999999")]
    count: u64,
}

// bump_memlock_rlimit function removed

fn print_stat(map: &Map, rows: u32) -> Result<()> {
    let mut rows = rows;

    println!(
        "{:<7} {:<16} {:<6} {:<6} {:<7} {:<7} {:<1} FILE",
        "TID", "COMM", "READS", "WRITES", "R_KB", "W_KB", "T"
    );

    let keys: Vec<_> = map.keys().collect();
    for key in keys {
        let value = map.lookup(&key, MapFlags::ANY)?.unwrap();
        map.delete(&key)?;

        if rows > 0 {
            // 使用强制类型转换替代 Plain trait
            let file_stat = unsafe { *(value.as_ptr() as *const types::file_stat) };

            let filename = CStr::from_bytes_until_nul(&file_stat.filename)?.to_str()?;
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
                &rev_filename[1..],
            );

            rows -= 1;
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    let opts = Command::parse();

    let mut skel_builder = FiletopSkelBuilder::default();
    if opts.verbose {
        skel_builder.obj_builder.debug(true);
    }

    // bump_memlock_rlimit call removed

    let mut open_obj = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_obj)?;

    if let Some(pid) = opts.pid {
        open_skel.maps.rodata_data.target_pid = pid; // Changed bss() to maps.rodata_data()
    }
    open_skel.maps.rodata_data.regular_file_only = !opts.all; // Changed bss() to maps.rodata_data()

    let mut skel = open_skel.load()?;
    skel.attach()?;

    let mut count = opts.count;
    while count > 0 {
        sleep(Duration::from_secs(opts.interval));
        if !opts.noclear {
            print!("\x1B[2J\x1B[1;1H");
        }
        print_stat(&skel.maps.entries, opts.rows)?; // Changed maps_mut() to maps()
        count -= 1;
    }
    Ok(())
}
