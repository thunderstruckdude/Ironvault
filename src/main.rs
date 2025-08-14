// src/main.rs
use anyhow::{bail, Context, Result};
use clap::Parser;
use nix::mount::{mount, umount2, MntFlags, MsFlags};
use nix::sched::{unshare, CloneFlags};
use nix::sys::stat::Mode;
use nix::unistd::{chdir, chroot, fork, ForkResult, geteuid};
use serde::Deserialize;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use sysinfo::{ProcessExt, System, SystemExt};
use uuid::Uuid;
use std::os::unix::process::CommandExt;

#[derive(Parser, Debug)]
#[command(name = "procbox", about = "ProcBox Phase1 MVP")]
struct Cli {
    #[arg(short, long, default_value = "policy.yaml")]
    policy: String,
    #[arg(last = true)]
    cmd: Vec<String>,
}

#[derive(Deserialize, Debug)]
struct Policy {
    name: Option<String>,
    filesystem: Option<Filesystem>,
    network: Option<Network>,
    limits: Option<Limits>,
    seccomp: Option<SeccompPolicy>,
}

#[derive(Deserialize, Debug)]
struct Filesystem {
    ro: Option<Vec<String>>,
    rw: Option<Vec<String>>,
    tmpfs: Option<Vec<String>>,
}

#[derive(Deserialize, Debug)]
struct Network {
    allow: bool,
}

#[derive(Deserialize, Debug)]
struct Limits {
    memory_mb: Option<u64>,
    cpu_seconds: Option<u64>,
}

#[derive(Deserialize, Debug)]
struct SeccompPolicy {
    mode: Option<String>, // "off" or "whitelist"
    allow_syscalls: Option<Vec<String>>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Read policy
    let yaml = fs::read_to_string(&cli.policy)
        .with_context(|| format!("Failed to read policy file {}", &cli.policy))?;
    let policy: Policy = serde_yaml::from_str(&yaml)?;

    if cli.cmd.is_empty() {
        bail!("No command provided to run inside sandbox");
    }

    // Generate ephemeral sandbox id
    let sandbox_id = Uuid::new_v4().to_string();
    let sandbox_root = format!("/tmp/procbox_{}", sandbox_id);

    println!("[*] Preparing sandbox {}", sandbox_id);
    prepare_overlay(&sandbox_root, &policy)?;

    // Try to unshare user+mount namespaces for isolation. If unprivileged userns is disabled, this call may fail.
    // In production: detect and fallback to setuid helper or require root.
    println!("[*] Unsharing namespaces (user,mount,pid,uts)...");
    // We'll unshare mount and pid & uts; userns unshare requires special mapping; for MVP, assume running as root or enabled userns.
    unshare(
        CloneFlags::CLONE_NEWNS
            | CloneFlags::CLONE_NEWPID
            | CloneFlags::CLONE_NEWUTS
            | CloneFlags::CLONE_NEWUSER
            | CloneFlags::CLONE_NEWNET,
    )
    .context("Failed to unshare namespaces; try running with root or enable unprivileged userns")?;

    // chdir and chroot into our prepared overlay as new root
    chdir(&sandbox_root).context("chdir to sandbox_root failed")?;
    chroot(".").context("chroot failed")?;
    chdir("/").context("chdir / after chroot failed")?;
    println!("[*] chrooted into {}", &sandbox_root);

    // If network not allowed, remove loopback interface inside this netns to effectively disable network.
    if let Some(net) = &policy.network {
        if !net.allow {
            // Simple approach: bring down loopback. Requires iproute2 or netlink; we call `ip` here for MVP.
            // Note: safer to use netlink via rtnetlink crate; using `ip` is pragmatic for MVP.
            println!("[*] Disabling network: bringing loopback down inside namespace");
            let _ = Command::new("ip")
                .args(["link", "set", "lo", "down"])
                .status()
                .context("Failed to run ip link set lo down; are iproute2 tools installed?")?;
        }
    }

    // Spawn the target inside new PID namespace: fork then exec in child so PID namespace takes effect.
    match unsafe { fork() }? {
        ForkResult::Child => {
            // Child is PID 1 in new PID NS; we want to exec the target.
            // Apply cgroup limits (we are running inside a new namespace but cgroup writes are global)
            let pid = nix::unistd::getpid().as_raw() as i32;
            if let Some(l) = &policy.limits {
                apply_cgroup_limits(pid, l.memory_mb.unwrap_or(0), l.cpu_seconds.unwrap_or(0))?;
            }

            // Apply seccomp filter before exec
            if let Some(sec) = &policy.seccomp {
                if sec.mode.as_deref() == Some("whitelist") {
                    let allowed = sec.allow_syscalls.clone().unwrap_or_default();
                    apply_seccomp_whitelist(allowed)?;
                }
            }

            // Exec the requested command
            let cmd0 = &cli.cmd[0];
            let cmd_args: Vec<&str> = cli.cmd.iter().skip(1).map(|s| s.as_str()).collect();

            // Ensure stdout/stderr are not buffered away (for easier capture).
            let error = Command::new(cmd0)
                .args(cmd_args)
                .stdin(Stdio::null())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .exec(); // replaces current process
            // If exec returns, it failed:
            eprintln!("exec failed: {:?}", error);
            std::process::exit(1);
        }
        ForkResult::Parent { child } => {
            // Parent monitors the child (child PID inside original namespace)
            println!("[*] Spawned sandboxed child pid (in parent ns): {}", child);
            let start = Instant::now();
            // Wait & enforce wall-clock cpu_seconds limit if configured
            loop {
                // Nonblocking check for child status
                match nix::sys::wait::waitpid(child, Some(nix::sys::wait::WaitPidFlag::WNOHANG)) {
                    Ok(nix::sys::wait::WaitStatus::StillAlive) => {
                        if let Some(l) = &policy.limits {
                            if l.cpu_seconds.unwrap_or(0) > 0 && start.elapsed() > Duration::from_secs(l.cpu_seconds.unwrap_or(0)) {
                                println!("[!] Wall-clock timeout exceeded; killing child");
                                let _ = nix::sys::signal::kill(child, nix::sys::signal::Signal::SIGKILL);
                                break;
                            }
                        }
                        std::thread::sleep(Duration::from_millis(300));
                        continue;
                    }
                    Ok(status) => {
                        println!("[*] Child exited: {:?}", status);
                        // collect telemetry
                        // Note: child pid in sysinfo is in host NS; we use child's pid variable.
                        let exit_code = match status {
                            nix::sys::wait::WaitStatus::Exited(_, code) => Some(code),
                            nix::sys::wait::WaitStatus::Signaled(_, sig, _) => {
                                println!("Child killed by signal {:?}", sig);
                                None
                            }
                            _ => None,
                        };
                        write_log(child.as_raw() as i32, exit_code)?;
                        break;
                    }
                    Err(e) => {
                        eprintln!("waitpid error: {:?}", e);
                        break;
                    }
                }
            }
        }
    }

    // Cleanup overlay (attempt unmounts)
    cleanup_overlay(&sandbox_root)?;

    Ok(())
}

/// Prepare overlay fs + binds according to policy under a sandbox root directory.
/// Simple overlay: lowerdirs = ro binds + system root, upperdir on tmp, workdir on tmp, mount overlay to sandbox_root
fn prepare_overlay(sandbox_root: &str, policy: &Policy) -> Result<()> {
    // create base dirs
    fs::create_dir_all(sandbox_root)?;
    fs::create_dir_all(format!("{}/upper", sandbox_root))?;
    fs::create_dir_all(format!("{}/work", sandbox_root))?;
    fs::create_dir_all(format!("{}/lower_ro", sandbox_root))?;

    // For each ro path => bind mount into lower_ro/path (readonly)
    if let Some(fs_policy) = &policy.filesystem {
        if let Some(ro_list) = &fs_policy.ro {
            for p in ro_list {
                let dest = format!("{}/lower_ro{}", sandbox_root, p);
                fs::create_dir_all(&dest)?;
                // bind mount p -> dest (recursive bind)
                mount(Some(Path::new(p)), Path::new(&dest), None::<&str>, MsFlags::MS_BIND | MsFlags::MS_REC, None::<&str>)?;
                // make readonly remount
                mount(Some(Path::new(&dest)), Path::new(&dest), None::<&str>, MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY | MsFlags::MS_REC, None::<&str>)?;
            }
        }
        // For rw paths, create directories in upper
        if let Some(rw_list) = &fs_policy.rw {
            for p in rw_list {
                let dest = format!("{}/upper{}", sandbox_root, p);
                fs::create_dir_all(&dest)?;
                // bind original dir (optional). For sandbox writeable overlay, we do not bind original
            }
        }
    }

    // Build overlay lowerdirs string: include our lower_ro plus an empty tmp lower if needed.
    // For MVP: we let lowerdir be the root of the host (but read-only) plus all /lower_ro entries. Simpler approach:
    // We'll create a lowerdir as ":" separated list of /tmp/procbox_<id>/lower_ro and "/" (read-only system).
    let lower = format!("{}/lower_ro:/", sandbox_root);
    let upper = format!("{}/upper", sandbox_root);
    let work = format!("{}/work", sandbox_root);

    // Mount overlay onto sandbox_root (note: sandbox_root already exists — remount over it)
    let opts = format!("lowerdir={},upperdir={},workdir={}", lower, upper, work);
    mount(Some("overlay"), Path::new(sandbox_root), Some("overlay"), MsFlags::empty(), Some(&opts))?;

    // create minimal /proc and /dev inside sandbox
    fs::create_dir_all(format!("{}/proc", sandbox_root))?;
    fs::create_dir_all(format!("{}/dev", sandbox_root))?;
    mount(Some("proc"), Path::new(&format!("{}/proc", sandbox_root)), Some("proc"), MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_NODEV, None::<&str>)?;

    Ok(())
}

/// Cleanup overlay mounts
fn cleanup_overlay(sandbox_root: &str) -> Result<()> {
    // Try unmount proc and the overlay
    let _ = umount2(Path::new(&format!("{}/proc", sandbox_root)), MntFlags::MNT_DETACH);
    let _ = umount2(Path::new(sandbox_root), MntFlags::MNT_DETACH);
    // best effort: remove directory
    let _ = fs::remove_dir_all(sandbox_root);
    Ok(())
}

/// Write a very simple telemetry JSON log for this run.
fn write_log(pid: i32, exit_code: Option<i32>) -> Result<()> {
    let mut s = System::new_all();
    s.refresh_all();
    let mut cpu = 0.0;
    let mut mem = 0u64;
    if let Some(p) = s.process(pid) {
        cpu = p.cpu_usage();
        mem = p.memory();
    }
    let j = serde_json::json!({
        "pid": pid,
        "cpu": cpu,
        "mem_kb": mem,
        "exit": exit_code,
    });
    let mut f = File::create("procbox_run_log.json")?;
    f.write_all(serde_json::to_string_pretty(&j)?.as_bytes())?;
    println!("[*] Wrote run log procbox_run_log.json");
    Ok(())
}

/// Apply cgroup v2 limits for the given pid. This function assumes cgroup v2 is mounted on /sys/fs/cgroup.
/// Creates /sys/fs/cgroup/procbox_<uuid> and writes memory.max and cpu.max and adds pid to cgroup.procs
fn apply_cgroup_limits(pid: i32, memory_mb: u64, _cpu_seconds: u64) -> Result<()> {
    let cg_path = format!("/sys/fs/cgroup/procbox_{}", Uuid::new_v4().to_string());
    fs::create_dir_all(&cg_path)?;
    if memory_mb > 0 {
        let bytes = memory_mb * 1024 * 1024;
        fs::write(format!("{}/memory.max", cg_path), bytes.to_string())?;
    }
    // For CPU, we'll set cpu.max to a large quota (no throttling), and rely on wall-clock kill for overall runtime.
    // If you want CPU throttling, write "<quota> <period>" to cpu.max.
    fs::write(format!("{}/cgroup.procs", cg_path), pid.to_string())?;
    println!("[*] Applied cgroup v2 limits in {}", cg_path);
    Ok(())
}

/// Apply a simple seccomp whitelist using libseccomp-rs
fn apply_seccomp_whitelist(allowed: Vec<String>) -> Result<()> {
    // Convert syscall names to numbers and add to filter
    // For MVP we create a filter that returns ERRNO for non-allowed syscalls
    use libseccomp::*;
    let mut ctx = ScmpFilterContext::new_filter(ScmpAction::Errno(libc::EPERM))?;
    // always allow essential syscalls for startup and signals: rt_sigreturn, sigreturn
    let essentials = vec!["rt_sigreturn", "sigreturn", "exit", "exit_group"];
    for name in essentials.into_iter().chain(allowed.iter().map(|s| s.as_str())) {
        if let Ok(num) = ScmpSyscall::from_name(name) {
            ctx.add_rule(ScmpAction::Allow, num)?;
        } else {
            println!("[!] unknown syscall name in policy: {}", name);
        }
    }
    // load filter
    ctx.load()?;
    println!("[*] Seccomp whitelist applied ({} allowed syscalls)", allowed.len());
    Ok(())
}
