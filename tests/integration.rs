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

/// The `Init:` line (printed before the socket is opened, so whether ICMP is
/// allowed does not matter) calls 127.0.0.1 loopback and, on Linux, puts its
/// source on `lo` with the /8, not on the default route's interface.
/// `--ascii`: the separator is ` | ` whatever the locale (CI runs without a
/// UTF-8 one).
#[test]
fn test_init_line_loopback() {
    let output = sping_timed(5)
        .args([
            "127.0.0.1",
            "--view",
            "classic",
            "-c",
            "1",
            "-W",
            "1",
            "--ascii",
        ])
        .output()
        .expect("failed to run");
    let stderr = String::from_utf8_lossy(&output.stderr);
    let init = stderr
        .lines()
        .find(|l| l.starts_with("Init:"))
        .unwrap_or_else(|| panic!("no Init line: {stderr}"));
    assert!(init.ends_with("target 127.0.0.1 | loopback"), "{init}");
    #[cfg(target_os = "linux")]
    assert!(init.starts_with("Init: if lo | 127.0.0.1/8 | "), "{init}");
}

/// macOS runs `route` and `ifconfig` from /sbin by absolute path: under
/// cron's PATH (/usr/bin:/bin, no /sbin) the loopback `Init:` line, with its
/// interface, prefix and gateway, is the one a PATH with /sbin gives.
#[cfg(target_os = "macos")]
#[test]
fn test_init_line_without_sbin_in_path() {
    let init_line = |path: &str| {
        let mut run = sping_timed(5).args([
            "127.0.0.1",
            "--view",
            "classic",
            "-c",
            "1",
            "-W",
            "1",
            "--ascii",
        ]);
        run.cmd.env("PATH", path);
        let output = run.output().expect("failed to run");
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        stderr
            .lines()
            .find(|l| l.starts_with("Init:"))
            .unwrap_or_else(|| panic!("no Init line: {stderr}"))
            .to_string()
    };
    assert_eq!(
        init_line("/usr/bin:/bin"),
        init_line("/usr/bin:/bin:/usr/sbin:/sbin")
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

// === TCP connect (`--tcp`): needs no ICMP permission, so nothing is skipped ===

/// A local listener and its port, as text for the command line.
fn tcp_listener() -> (std::net::TcpListener, String) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port().to_string();
    (listener, port)
}

/// A port nobody listens on: bound, then released.
fn tcp_closed_port() -> String {
    tcp_listener().1
}

/// A batch file under Cargo's scratch directory for integration tests.
fn batch_file(name: &str, hosts: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    std::fs::write(&path, hosts).unwrap();
    path.to_string_lossy().into_owned()
}

/// A target that never answers on `port`: 127.0.0.2 (local on Linux) with a
/// listener whose queue is full, so the kernel drops every new SYN. Keep
/// both values alive while probing.
#[cfg(target_os = "linux")]
fn tcp_silent_target(port: &str) -> (socket2::Socket, std::net::TcpStream) {
    use socket2::{Domain, SockAddr, Socket, Type};
    let addr: std::net::SocketAddr = format!("127.0.0.2:{port}").parse().unwrap();
    let listener = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
    listener.bind(&SockAddr::from(addr)).unwrap();
    listener.listen(0).unwrap();
    // A backlog of 0 holds one pending connection: this one.
    let queued = std::net::TcpStream::connect(addr).unwrap();
    (listener, queued)
}

#[test]
fn test_tcp_open_port_classic() {
    let (_listener, port) = tcp_listener();
    let output = sping_timed(15)
        .args([
            "127.0.0.1",
            "--tcp",
            &port,
            "-c",
            "3",
            "-i",
            "200",
            "--view",
            "classic",
        ])
        .output()
        .expect("failed to run");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.timed_out, "did not stop after -c 3");
    assert_eq!(output.status.code(), Some(0), "stderr: {stderr}");
    assert!(
        stderr.contains(&format!("target 127.0.0.1 tcp/{port}")),
        "{stderr}"
    );
    assert!(
        stdout.contains(&format!("Connected to 127.0.0.1:{port}: seq=1 ")),
        "{stdout}"
    );
    assert!(
        stdout.contains(&format!("--- 127.0.0.1 tcp/{port} statistics ---")),
        "{stdout}"
    );
    assert!(
        stdout.contains("3 connects, 3 answered (0 refused), 0.0% loss"),
        "{stdout}"
    );
}

#[test]
fn test_tcp_refused_port_is_an_answer() {
    let port = tcp_closed_port();
    // -W 1: a refusal comes at once, also on Windows (no SYN retries).
    let output = sping_timed(30)
        .args([
            "127.0.0.1",
            "--tcp",
            &port,
            "-c",
            "2",
            "-i",
            "200",
            "-W",
            "1",
            "--view",
            "classic",
        ])
        .output()
        .expect("failed to run");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!output.timed_out, "did not stop after -c 2");
    assert_eq!(output.status.code(), Some(0), "{stdout}");
    assert!(
        stdout.contains(&format!("Refused by 127.0.0.1:{port}: seq=1 ")),
        "{stdout}"
    );
    assert!(
        stdout.contains("2 connects, 2 answered (2 refused), 0.0% loss"),
        "{stdout}"
    );
}

#[test]
fn test_tcp_json_fields() {
    let (_listener, port) = tcp_listener();
    let output = sping_timed(15)
        .args([
            "127.0.0.1",
            "--tcp",
            &port,
            "-c",
            "2",
            "-i",
            "200",
            "--view",
            "json",
        ])
        .output()
        .expect("failed to run");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<serde_json::Value> = stdout
        .lines()
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("invalid JSON '{l}': {e}")))
        .collect();
    assert_eq!(lines.len(), 2, "{stdout}");
    for (i, val) in lines.iter().enumerate() {
        assert_eq!(val["probe"], "tcp");
        assert_eq!(val["port"], port.parse::<u64>().unwrap());
        assert_eq!(val["tcp_state"], "open");
        assert_eq!(val["refused"], 0);
        assert_eq!(val["received"], i as u64 + 1);
        assert!(val["ttl"].is_null(), "TCP has no TTL: {val}");
    }
}

/// A refused port is in each JSON line's diagnosis, with its port; in the
/// batch JSON too, which has no gateway or WAN probe to report.
#[test]
fn test_tcp_refusal_in_the_json_diagnosis() {
    let port = tcp_closed_port();
    let hosts = batch_file("diagnosis_batch.txt", "127.0.0.1\n");
    for batch in [false, true] {
        let common = [
            "--tcp", &port, "-c", "2", "-i", "200", "-W", "1", "--view", "json",
        ];
        let timed = sping_timed(30).args(common);
        let timed = if batch {
            timed.args(["--batch", &hosts])
        } else {
            timed.args(["127.0.0.1"])
        };
        let output = timed.output().expect("failed to run");
        assert!(!output.timed_out, "did not stop after -c 2");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let lines: Vec<serde_json::Value> = stdout
            .lines()
            .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("invalid JSON '{l}': {e}")))
            .collect();
        assert_eq!(lines.len(), if batch { 1 } else { 2 }, "{stdout}");
        for val in &lines {
            assert_eq!(val["tcp_state"], "refused", "{val}");
            let diagnosis = val["diagnosis"].as_array().expect("no diagnosis");
            assert_eq!(
                diagnosis[0],
                serde_json::json!({"code": "tcp_refused", "port": port.parse::<u64>().unwrap()}),
                "{val}"
            );
            if batch {
                assert!(
                    val.get("gateway").is_none() && val.get("wan").is_none(),
                    "{val}"
                );
            }
        }
    }
}

#[test]
fn test_tcp_port_and_size_rejected() {
    for args in [
        ["127.0.0.1", "--tcp", "0", "-c", "1"],
        ["127.0.0.1", "--tcp", "65536", "-c", "1"],
        ["127.0.0.1", "--tcp", "80", "-s", "56"],
    ] {
        let output = sping_cmd().args(args).output().expect("failed to run");
        assert_eq!(output.status.code(), Some(2), "{args:?}");
    }
}

#[test]
fn test_tcp_unusable_source_is_an_error() {
    let (_listener, port) = tcp_listener();
    let output = sping_timed(15)
        .args(["127.0.0.1", "-S", "192.0.2.7", "--tcp", &port, "-c", "1"])
        .output()
        .expect("failed to run");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("cannot prepare the TCP probe"), "{stderr}");
}

#[cfg(target_os = "linux")]
#[test]
fn test_tcp_multi_target_needs_every_answer() {
    let (_listener, port) = tcp_listener();
    let _silent = tcp_silent_target(&port);
    let output = sping_timed(30)
        .args([
            "127.0.0.1",
            "127.0.0.2",
            "--tcp",
            &port,
            "-c",
            "2",
            "-i",
            "200",
            "-W",
            "1",
        ])
        .output()
        .expect("failed to run");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!output.timed_out, "did not stop after -c 2");
    assert_eq!(output.status.code(), Some(1), "{stdout}");
    assert!(
        stdout.contains(&format!(
            "--- 127.0.0.1 (127.0.0.1) tcp/{port} statistics ---"
        )),
        "{stdout}"
    );
    assert!(
        stdout.contains("2 connects, 2 answered (0 refused), 0% loss"),
        "{stdout}"
    );
    assert!(
        stdout.contains("2 connects, 0 answered (0 refused), 100% loss"),
        "{stdout}"
    );
}

/// Two loopback targets: one listening, one refusing; both answer. 127.0.0.2
/// is local on Linux only.
#[cfg(target_os = "linux")]
#[test]
fn test_tcp_multi_target_refused_counts() {
    let (_listener, port) = tcp_listener();
    let output = sping_timed(30)
        .args([
            "127.0.0.1",
            "127.0.0.2",
            "--tcp",
            &port,
            "-c",
            "2",
            "-i",
            "200",
        ])
        .output()
        .expect("failed to run");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(0), "{stdout}");
    assert!(
        stdout.contains("2 connects, 2 answered (2 refused), 0% loss"),
        "{stdout}"
    );
}

#[test]
fn test_tcp_batch_exit_codes() {
    let (_listener, port) = tcp_listener();

    let answered = batch_file("tcp-batch-answered.txt", "127.0.0.1\n");
    let output = sping_timed(30)
        .args(["--batch", &answered, "--tcp", &port, "-c", "2", "-i", "200"])
        .output()
        .expect("failed to run");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(0), "{stdout}");
    assert!(stdout.contains("2/2  0%"), "{stdout}");
    assert!(stdout.contains(&format!("tcp/{port} open")), "{stdout}");

    // A source address that cannot be used is a local error for the batch.
    let output = sping_timed(30)
        .args([
            "--batch",
            &answered,
            "-S",
            "192.0.2.7",
            "--tcp",
            &port,
            "-c",
            "1",
        ])
        .output()
        .expect("failed to run");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("cannot prepare the TCP probe"), "{stderr}");
}

#[cfg(target_os = "linux")]
#[test]
fn test_tcp_batch_needs_every_answer() {
    let (_listener, port) = tcp_listener();
    let _silent = tcp_silent_target(&port);
    let mixed = batch_file("tcp-batch-mixed.txt", "127.0.0.1\n127.0.0.2\n");
    let output = sping_timed(30)
        .args([
            "--batch", &mixed, "--tcp", &port, "-c", "2", "-i", "200", "-W", "1", "--view", "json",
        ])
        .output()
        .expect("failed to run");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(1), "{stdout}");
    let lines: Vec<serde_json::Value> = stdout
        .lines()
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("invalid JSON '{l}': {e}")))
        .collect();
    assert_eq!(lines.len(), 2, "{stdout}");
    assert_eq!(lines[0]["tcp_state"], "open");
    assert_eq!(lines[0]["received"], 2);
    assert_eq!(lines[1]["tcp_state"], "timeout");
    assert_eq!(lines[1]["received"], 0);
    assert!(lines.iter().all(|l| l["probe"] == "tcp"), "{stdout}");
}
