use clap::{Parser, Subcommand};
use std::process::{Command, Stdio};
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use sysinfo::{System, SystemExt, ProcessExt};
use serde::Serialize;
use nix::unistd::{chroot, chdir};
use nix::sched::{unshare, CloneFlags};
use std::time::{Duration, Instant};

#[derive(Parser)]
#[command(name = "ProcBox", about = "Lightweight Process Sandbox in Rust")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Run {
        binary: String,
        #[arg(long, default_value = "0")]
        mem: usize, // MB
        #[arg(long, default_value = "0")]
        cpu: usize, // seconds
        #[arg(long, default_value = "on")]
        net: String, // on/off
    },
}

#[derive(Serialize)]
struct LogEntry {
    pid: i32,
    cpu_usage: f32,
    mem_usage_kb: u64,
    exit_code: Option<i32>,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Run { binary, mem, cpu, net } => {
            println!("[*] Starting sandbox...");

            // 1. Setup filesystem jail
            setup_chroot("/tmp/sandbox_root")?;

            // 2. Apply network restriction if needed
            if net == "off" {
                disable_network()?;
            }

            // 3. Run process inside sandbox with resource limits
            run_with_limits(&binary, mem, cpu)?;
        }
    }

    Ok(())
}

/// Setup chroot jail
fn setup_chroot(dir: &str) -> anyhow::Result<()> {
    println!("[*] Setting up chroot to {}", dir);

    if !Path::new(dir).exists() {
        fs::create_dir_all(dir)?;
    }

    // Change root
    chroot(dir)?;
    chdir("/")?;

    Ok(())
}

/// Disable network using namespaces
fn disable_network() -> anyhow::Result<()> {
    println!("[*] Disabling network...");
    unsafe {
        unshare(CloneFlags::CLONE_NEWNET)?;
    }
    Ok(())
}

/// Create cgroup and apply CPU/mem limits
fn apply_cgroup_limits(pid: i32, mem_limit_mb: usize, cpu_limit_sec: usize) -> anyhow::Result<()> {
    let cgroup_path = "/sys/fs/cgroup/procbox_sandbox";

    // Create cgroup dir
    fs::create_dir_all(cgroup_path)?;

    // Set memory limit (in bytes)
    if mem_limit_mb > 0 {
        let mem_limit_bytes = mem_limit_mb * 1024 * 1024;
        fs::write(format!("{}/memory.max", cgroup_path), mem_limit_bytes.to_string())?;
    }

    // Set CPU limit (in microseconds per 100ms period)
    // Example: For 2 seconds total allowed time over the process life, we can't directly limit total time in cgroups.
    // Instead, we throttle CPU usage rate. (For strict wall clock, we kill manually below.)
    if cpu_limit_sec > 0 {
        let period = 100000; // 100ms
        let quota = (period as u64) * 1; // 100% single-core
        fs::write(format!("{}/cpu.max", cgroup_path), format!("{} {}", quota, period))?;
    }

    // Add process to cgroup
    fs::write(format!("{}/cgroup.procs", cgroup_path), pid.to_string())?;

    Ok(())
}

/// Run process in sandbox with limits
fn run_with_limits(binary: &str, mem_limit: usize, cpu_limit: usize) -> anyhow::Result<()> {
    let start = Instant::now();

    let mut child = Command::new(binary)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let pid = child.id() as i32;
    println!("[*] Process PID: {}", pid);

    // Apply cgroup limits
    apply_cgroup_limits(pid, mem_limit, cpu_limit)?;

    let sys = System::new_all();

    // Monitor loop
    loop {
        if let Some(status) = child.try_wait()? {
            println!("[*] Process exited with {:?}", status.code());
            log_process(pid, status.code())?;
            break;
        }

        // Enforce wall clock CPU time limit
        if cpu_limit > 0 && start.elapsed() > Duration::from_secs(cpu_limit as u64) {
            println!("[!] CPU time exceeded, killing process...");
            child.kill()?;
        }

        std::thread::sleep(Duration::from_millis(500));
    }

    Ok(())
}

/// Log process stats to JSON
fn log_process(pid: i32, exit_code: Option<i32>) -> anyhow::Result<()> {
    let mut sys = System::new_all();
    sys.refresh_all();

    if let Some(proc) = sys.process(pid) {
        let log_entry = LogEntry {
            pid,
            cpu_usage: proc.cpu_usage(),
            mem_usage_kb: proc.memory(),
            exit_code,
        };

        let json = serde_json::to_string_pretty(&log_entry)?;
        let mut file = File::create("procbox_log.json")?;
        file.write_all(json.as_bytes())?;
        println!("[*] Log saved to procbox_log.json");
    } else {
        println!("[!] Process info not found (may have exited quickly)");
    }

    Ok(())
}
