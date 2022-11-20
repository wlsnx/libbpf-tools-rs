use anyhow::{bail, Result};
use clap::Parser;
use libbpf_rs::PerfBufferBuilder;
use object::{File, Object, ObjectSymbol};
use plain::Plain;
use regex::Regex;
use std::time::Duration;
use time::{macros::format_description, OffsetDateTime};

mod bashreadline {
    include!(concat!(env!("OUT_DIR"), "/bashreadline.skel.rs"));
}

use bashreadline::*;

#[derive(Debug, Parser)]
struct Command {
    #[arg(short, long)]
    shared: Option<String>,
    #[arg(short, long, default_value_t)]
    verbose: bool,
}

unsafe impl Plain for bashreadline_bss_types::str_t {}

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
    let mut event = bashreadline_bss_types::str_t::default();
    plain::copy_from_bytes(&mut event, data).expect("Data buffer was too short");

    let now = if let Ok(now) = OffsetDateTime::now_local() {
        let format = format_description!("[hour]:[minute]:[second]");
        now.format(&format)
            .unwrap_or_else(|_| "00:00:00".to_string())
    } else {
        "00:00:00".to_string()
    };

    let index = event.str.iter().position(|&c| c == 0).unwrap();
    let task = std::str::from_utf8(&event.str[..index]).unwrap();

    println!("{:<9} {:<7} {}", now, event.pid, task)
}

fn handle_lost_events(cpu: i32, count: u64) {
    eprintln!("Lost {} events on CPU {}", count, cpu);
}

fn get_elf_func_offset(path: &str, sym_name: &str) -> Result<u64> {
    let data = std::fs::read(path)?;
    let file = File::parse(&*data)?;

    for symbol in file.dynamic_symbols() {
        if let Ok(name) = symbol.name() {
            if name == sym_name {
                return Ok(symbol.address());
            }
        }
    }

    bail!("could not find {} in {}", sym_name, path)
}

fn find_readline_so() -> Result<(String, u64)> {
    let bash_path = "/bin/bash";
    let sym_name = "readline";

    let offset = get_elf_func_offset(bash_path, sym_name)?;
    if offset > 0 {
        return Ok((bash_path.to_string(), offset));
    }

    let ldd = std::process::Command::new("ldd")
        .arg("/bin/bash")
        .output()?;
    let output = std::str::from_utf8(&ldd.stdout)?;
    let pattern = Regex::new(r"readline\.so[^ ]* => ([^ ]+)")?;

    if let Some(capture) = pattern.captures_iter(output).next() {
        let path = capture.get(1).unwrap().as_str();
        let offset = get_elf_func_offset(path, sym_name)?;

        if offset > 0 {
            return Ok((path.to_string(), offset));
        }
    }

    bail!("failed to find readline")
}

fn main() -> Result<()> {
    let opts = Command::parse();

    let mut skel_builder = BashreadlineSkelBuilder::default();
    if opts.verbose {
        skel_builder.obj_builder.debug(true);
    }

    bump_memlock_rlimit()?;
    let open_skel = skel_builder.open()?;

    let mut skel = open_skel.load()?;

    let (readline, offset) = find_readline_so()?;

    let _link = skel
        .progs_mut()
        .printret()
        .attach_uprobe(true, -1, readline, offset as usize)?;
    // skel.attach()?;

    let perf = PerfBufferBuilder::new(skel.maps_mut().events())
        .sample_cb(handle_event)
        .lost_cb(handle_lost_events)
        .build()?;

    println!("{:<9} {:<7} {}", "TIME", "PID", "COMMAND");

    loop {
        perf.poll(Duration::from_millis(100))?;
    }
}
