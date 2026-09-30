use std::io::Read;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

fn sping_cmd() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sping"));
    cmd.env("TERM", "dumb");
    cmd
}

/// `sping` under a watchdog. Stands in for timeout(1), which macOS does not
/// ship and which on Windows resolves to an unrelated system tool.
struct Timed {
    cmd: Command,
    limit: Duration,
}

struct TimedOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    /// The watchdog had to stop the process.
    timed_out: bool,
}

fn sping_timed(secs: u64) -> Timed {
    Timed {
        cmd: sping_cmd(),
        limit: Duration::from_secs(secs),
    }
}

impl Timed {
    fn args<const N: usize>(mut self, args: [&str; N]) -> Self {
        self.cmd.args(args);
        self
    }

    fn output(mut self) -> std::io::Result<TimedOutput> {
        let mut child = self
            .cmd
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        // Drain both pipes while waiting: a child blocked on a full pipe
        // would never exit.
        let stdout = drain(child.stdout.take());
        let stderr = drain(child.stderr.take());

        let deadline = Instant::now() + self.limit;
        let mut timed_out = false;
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if Instant::now() >= deadline {
                timed_out = true;
                terminate(&mut child)?;
                break child.wait()?;
            }
            std::thread::sleep(Duration::from_millis(20));
        };

        Ok(TimedOutput {
            status,
            stdout: stdout.join().expect("stdout reader panicked"),
            stderr: stderr.join().expect("stderr reader panicked"),
            timed_out,
        })
    }
}

fn drain<R: Read + Send + 'static>(pipe: Option<R>) -> JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut pipe) = pipe {
            let _ = pipe.read_to_end(&mut buf);
        }
        buf
    })
}

/// SIGTERM, as timeout(1) sends: sping shuts down cleanly on it.
#[cfg(unix)]
fn terminate(child: &mut Child) -> std::io::Result<()> {
    // SAFETY: the child has not been reaped yet (`try_wait` returned `None`),
    // so its pid still names this process.
    if unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(unix))]
fn terminate(child: &mut Child) -> std::io::Result<()> {
    child.kill()
}

// === CLI parsing ===

#[test]
fn test_help_flag() {
    let output = sping_cmd().arg("--help").output().expect("failed to run");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("sping"));
    assert!(stdout.contains("TARGET"));
    assert!(stdout.contains("--view"));
    assert!(stdout.contains("--interface"));
    assert!(stdout.contains("--source"));
}

#[test]
fn test_version_flag() {
    let output = sping_cmd()
        .arg("--version")
        .output()
        .expect("failed to run");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("sping"));
}

#[test]
fn test_no_target_error() {
    let output = sping_cmd().output().expect("failed to run");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("TARGET"));
}

#[test]
fn test_list_interfaces() {
    let output = sping_cmd()
        .arg("--list-interfaces")
        .output()
        .expect("failed to run");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.is_empty());
}

// === Input validation ===

#[test]
fn test_invalid_source_ip_error() {
    let output = sping_cmd()
        .args(["-S", "not-an-ip", "8.8.8.8"])
        .output()
        .expect("failed to run");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid source IP"),
        "Expected source IP error, got: {stderr}"
    );
}

#[test]
fn test_invalid_interface_error() {
    let output = sping_cmd()
        .args(["-I", "nonexistent99", "8.8.8.8"])
        .output()
        .expect("failed to run");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not found"),
        "Expected interface error, got: {stderr}"
    );
}

#[test]
fn test_dns_resolution_failure() {
    let output = sping_cmd()
        .arg("this-host-definitely-does-not-exist.invalid")
        .output()
        .expect("failed to run");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("DNS") || stderr.contains("resolution"),
        "Expected DNS error, got: {stderr}"
    );
}

// === TTY auto-detection ===

#[test]
fn test_tty_fallback_to_classic() {
    // When piped, compact should fall back to classic
    let output = sping_timed(3)
        .args(["127.0.0.1", "-i", "200"])
        .output()
        .expect("failed to run");
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Should get classic-style output (Reply from...) not escape codes
    assert!(
        stderr.contains("falling back to classic")
            || stdout.contains("Reply from")
            || stderr.contains("ICMP"),
        "Expected classic fallback, got stderr={stderr} stdout={stdout}"
    );
}

// === JSON snapshot tests ===

#[test]
fn test_json_valid_structure() {
    let output = sping_timed(3)
        .args(["127.0.0.1", "--view", "json", "-i", "200"])
        .output()
        .expect("failed to run");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if stderr.contains("ICMP") || stderr.contains("failed") {
        return; // skip if no ICMP permission
    }

    for line in stdout.lines().take(3) {
        if line.trim().is_empty() {
            continue;
        }
        let val: serde_json::Value =
            serde_json::from_str(line).unwrap_or_else(|e| panic!("Invalid JSON '{line}': {e}"));

        // Required fields always present
        assert!(val.get("target_host").is_some(), "missing target_host");
        assert!(val.get("target_ip").is_some(), "missing target_ip");
        assert!(val.get("seq").is_some(), "missing seq");
        assert!(val.get("sent").is_some(), "missing sent");
        assert!(val.get("received").is_some(), "missing received");
        assert!(val.get("loss_pct").is_some(), "missing loss_pct");
        assert!(val.get("quality").is_some(), "missing quality");
        assert!(val.get("quality_score").is_some(), "missing quality_score");
        assert!(val.get("trend").is_some(), "missing trend");
    }
}

#[test]
fn test_json_unknown_before_enough_data() {
    let output = sping_timed(2)
        .args(["127.0.0.1", "--view", "json", "-i", "200"])
        .output()
        .expect("failed to run");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("ICMP") || stderr.contains("failed") {
        return;
    }

    // First line should have quality = "unknown" (not enough data)
    if let Some(first) = stdout.lines().next()
        && let Ok(val) = serde_json::from_str::<serde_json::Value>(first)
    {
        let q = val.get("quality").and_then(|v| v.as_str());
        assert_eq!(
            q,
            Some("unknown"),
            "First probe should have quality='unknown'"
        );
    }
}

#[test]
fn test_json_pipe_to_tool() {
    // Simulate piping: JSON should not contain escape codes
    let output = sping_timed(2)
        .args(["127.0.0.1", "--view", "json", "-i", "200"])
        .output()
        .expect("failed to run");

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if line.trim().is_empty() {
            continue;
        }
        assert!(
            !line.contains("\x1b["),
            "JSON should not contain ANSI escape codes: {line}"
        );
    }
}

// === Classic view ===

#[test]
fn test_classic_view_localhost() {
    let output = sping_timed(2)
        .args(["127.0.0.1", "--view", "classic", "-i", "200"])
        .output()
        .expect("failed to run");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stdout.contains("Reply from") || stderr.contains("ICMP") || stderr.contains("failed"),
        "Expected reply or socket error, got stdout={stdout} stderr={stderr}"
    );
}

// === Ping parity ===

#[test]
fn test_help_shows_ping_parity_flags() {
    let output = sping_cmd().arg("--help").output().expect("failed to run");
    let stdout = String::from_utf8_lossy(&output.stdout);
    for flag in [
        "--count",
        "--timeout",
        "--size",
        "--ttl",
        "--quiet",
        "--ascii",
    ] {
        assert!(stdout.contains(flag), "missing {flag} in --help");
    }
}

#[test]
fn test_count_flag_terminates_classic() {
    // -c now works in every view: the process must exit on its own,
    // well before the 15s watchdog.
    let output = sping_timed(15)
        .args(["127.0.0.1", "-c", "2", "-i", "200", "--view", "classic"])
        .output()
        .expect("failed to run");
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("ICMP") || stderr.contains("failed") {
        return; // no ICMP permission in this environment
    }
    assert!(!output.timed_out, "sping -c 2 did not terminate by itself");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("statistics"),
        "missing final summary: {stdout}"
    );
}

#[test]
fn test_exit_code_zero_on_replies() {
    let output = sping_timed(15)
        .args(["127.0.0.1", "-c", "1", "-i", "200", "--view", "classic"])
        .output()
        .expect("failed to run");
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("ICMP") || stderr.contains("failed") {
        return;
    }
    assert_eq!(output.status.code(), Some(0), "stderr: {stderr}");
}

#[test]
fn test_exit_code_two_on_usage_error() {
    let output = sping_cmd()
        .args(["-S", "not-an-ip", "8.8.8.8"])
        .output()
        .expect("failed to run");
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn test_quiet_suppresses_probe_lines() {
    let output = sping_timed(15)
        .args([
            "127.0.0.1",
            "-c",
            "2",
            "-q",
            "-i",
            "200",
            "--view",
            "classic",
        ])
        .output()
        .expect("failed to run");
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("ICMP") || stderr.contains("failed") {
        return;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("Reply from"),
        "quiet mode printed probe lines: {stdout}"
    );
    assert!(stdout.contains("statistics"), "missing summary: {stdout}");
}

#[test]
fn test_invalid_interval_rejected() {
    let output = sping_cmd()
        .args(["127.0.0.1", "-i", "5"])
        .output()
        .expect("failed to run");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("interval"), "got: {stderr}");
}

// === Multi-target ===

#[test]
fn test_multi_target_dedup() {
    // Duplicate targets should be deduplicated
    let output = sping_timed(2)
        .args(["127.0.0.1", "127.0.0.1", "--view", "classic", "-i", "500"])
        .output()
        .expect("failed to run");

    let stderr = String::from_utf8_lossy(&output.stderr);
    // With dedup, only 1 target → single-target mode (classic), not multi
    // OR if both kept, the classic output should work fine
    assert!(
        !stderr.contains("panic"),
        "Multi-target with dupes should not panic"
    );
}
