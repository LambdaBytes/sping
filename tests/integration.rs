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
    // As before 1.8 (`--ip` is the full view): `name ip/prefix`, IPv4, no
    // loopback.
    for line in stdout.lines().filter(|l| *l != "No interfaces detected.") {
        let (_name, address) = line.rsplit_once(' ').expect("name and address");
        let (ip, prefix) = address.split_once('/').expect("ip/prefix");
        let ip: std::net::Ipv4Addr = ip.parse().unwrap_or_else(|_| panic!("{line}"));
        assert!(!ip.is_loopback(), "{line}");
        assert!(prefix.parse::<u8>().is_ok(), "{line}");
    }
}

/// `--ip`: every address, the loopback's among them (whatever the system
/// calls that interface), then the sources and the gateway.
#[test]
fn test_ip_lists_the_host_addresses() {
    let output = sping_timed(10)
        .args(["--ip"])
        .output()
        .expect("failed to run");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout
            .lines()
            .any(|l| l.contains("127.0.0.1/8") && l.ends_with("loopback")),
        "{stdout}"
    );
    assert!(
        stdout
            .lines()
            .any(|l| l.starts_with("Source ") && l.contains("to 1.1.1.1")),
        "{stdout}"
    );
    assert!(
        stdout.lines().any(|l| l.starts_with("Gateway ")),
        "{stdout}"
    );
}

/// `--ip --view json`: one object, the loopback among the addresses and
/// each family's source named by its reference.
#[test]
fn test_ip_json() {
    let output = sping_timed(10)
        .args(["--ip", "--view", "json"])
        .output()
        .expect("failed to run");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let value: serde_json::Value = serde_json::from_str(stdout.trim()).expect("one JSON object");
    let addresses: Vec<&serde_json::Value> = value["interfaces"]
        .as_array()
        .expect("interfaces")
        .iter()
        .flat_map(|i| i["addresses"].as_array().expect("addresses"))
        .collect();
    assert!(
        addresses
            .iter()
            .any(|a| a["ip"] == "127.0.0.1" && a["kind"] == "loopback" && a["prefix_len"] == 8),
        "{value}"
    );
    assert_eq!(value["source"]["ipv4"]["to"], "1.1.1.1");
    assert_eq!(value["source"]["ipv6"]["to"], "2606:4700:4700::1111");
    assert!(value["gateway"].get("ipv4").is_some(), "{value}");
    // Only `--external` asks a STUN server.
    assert!(value.get("external").is_none(), "{value}");
}

/// `--ip` is about this host: a target is a usage error, not ignored.
#[test]
fn test_ip_takes_no_target() {
    let output = sping_cmd()
        .args(["--ip", "127.0.0.1"])
        .output()
        .expect("failed to run");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("cannot be used with") && stderr.contains("--ip"),
        "{stderr}"
    );
}

/// `--external` asks a third party: only with `--ip`, and only a server
/// that can be one.
#[test]
fn test_external_needs_ip_and_a_server() {
    let output = sping_cmd()
        .args(["--external"])
        .output()
        .expect("failed to run");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--ip"), "{stderr}");
    for (server, says) in [
        ("stun.example.com:0", "not a port"),
        (":::1", "not an IPv6 address"),
        ("[::g]:3478", "not an IPv6 address"),
    ] {
        let output = sping_cmd()
            .args(["--ip", "--external", server])
            .output()
            .expect("failed to run");
        assert_eq!(output.status.code(), Some(2), "{server}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(says), "{server}: {stderr}");
    }
}

/// `--ip --external` to a server that is not there: the host's addresses
/// all the same (exit 0) and the external IPv4 address unknown, within the
/// query's budget; an IPv4 server is not asked for IPv6.
#[test]
fn test_external_without_a_server() {
    let start = Instant::now();
    let output = sping_timed(10)
        .args(["--ip", "--external", "127.0.0.1:9", "--view", "json"])
        .output()
        .expect("failed to run");
    assert!(
        start.elapsed() < Duration::from_secs(6),
        "{:?}",
        start.elapsed()
    );
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let value: serde_json::Value = serde_json::from_str(stdout.trim()).expect("one JSON object");
    let external = &value["external"];
    assert_eq!(external["server"], "127.0.0.1:9", "{value}");
    assert_eq!(external["ipv4"]["asked"], "127.0.0.1", "{value}");
    assert!(external["ipv4"]["unknown"].is_string(), "{value}");
    assert!(external["ipv4"].get("ip").is_none(), "{value}");
    assert_eq!(external["ipv6"], serde_json::Value::Null, "{value}");
    assert!(value["interfaces"].as_array().is_some(), "{value}");
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

/// A misspelt view is a usage error; it was taken as the compact view.
#[test]
fn test_unknown_view_is_refused() {
    let output = sping_cmd()
        .args(["127.0.0.1", "-c", "1", "--view", "jsno"])
        .output()
        .expect("failed to run");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("invalid value 'jsno'"), "{stderr}");
}

/// `-o` writes batch mode's output; without `--batch` it was ignored, with
/// exit 0 and no file.
#[test]
fn test_output_file_needs_batch() {
    let path = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("o-without-batch.txt");
    let _ = std::fs::remove_file(&path);
    let output = sping_cmd()
        .args(["127.0.0.1", "-c", "1", "-o", path.to_str().unwrap()])
        .output()
        .expect("failed to run");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--batch"), "{stderr}");
    assert!(!path.exists());
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
        "--icmp",
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

/// Several targets are the live table, which needs a terminal. With stdout a
/// pipe there is no table (its escape sequences went into the pipe, and the
/// note said "falling back to classic"), only each target's summary; a view
/// the table is not is refused (it was ignored).
#[test]
fn test_several_targets_piped_print_only_their_summaries() {
    let piped = sping_timed(10)
        .args(["127.0.0.1", "127.0.0.2", "-c", "1", "-i", "200", "-W", "1"])
        .output()
        .expect("failed to run");
    assert!(!piped.timed_out);
    let stdout = String::from_utf8_lossy(&piped.stdout);
    let stderr = String::from_utf8_lossy(&piped.stderr);
    assert!(!stdout.contains('\x1b'), "{stdout:?}");
    // The summaries need probes; the note comes before the socket is opened.
    if stderr.contains("failed to create ICMP socket") {
        eprintln!("no ICMP permission here: the summaries not checked");
    } else {
        for host in ["127.0.0.1", "127.0.0.2"] {
            assert!(
                stdout.contains(&format!("--- {host} ({host}) sping statistics ---")),
                "{stdout}"
            );
        }
    }
    assert!(stderr.contains("no live table"), "{stderr}");
    assert!(!stderr.contains("falling back to classic"), "{stderr}");

    let json = sping_timed(5)
        .args([
            "127.0.0.1",
            "127.0.0.2",
            "-c",
            "1",
            "-i",
            "200",
            "--view",
            "json",
        ])
        .output()
        .expect("failed to run");
    assert_eq!(json.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&json.stderr);
    assert!(
        stderr.contains("--view json works with one target"),
        "{stderr}"
    );
}

// === Keys and terminals (a pseudo-terminal: Unix) ===

/// A pseudo-terminal: sping on the slave side sees a terminal, as in a
/// terminal window; the test reads the screen and types on the master side.
#[cfg(unix)]
fn open_pty() -> (std::fs::File, std::fs::File) {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::OpenOptionsExt;
    // `ptsname` returns a static buffer: one caller at a time.
    static PTSNAME: std::sync::Mutex<()> = std::sync::Mutex::new(());

    // SAFETY: `posix_openpt` returns a new descriptor (checked), owned by
    // the `File` from here on.
    let master = unsafe {
        let fd = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
        assert!(fd >= 0, "posix_openpt: {}", std::io::Error::last_os_error());
        std::fs::File::from_raw_fd(fd)
    };
    let fd = master.as_raw_fd();
    let os_error = std::io::Error::last_os_error;
    // SAFETY: `fd` is the open master.
    unsafe {
        assert_eq!(libc::grantpt(fd), 0, "grantpt: {}", os_error());
        assert_eq!(libc::unlockpt(fd), 0, "unlockpt: {}", os_error());
    }
    let name = {
        let _one = PTSNAME.lock().unwrap();
        // SAFETY: `fd` is an unlocked master; the static buffer is copied
        // before the lock is released.
        unsafe {
            let ptr = libc::ptsname(fd);
            assert!(!ptr.is_null(), "ptsname");
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap().to_owned()
        }
    };
    let slave = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOCTTY)
        .open(name)
        .unwrap();
    // 80 x 24, room for every view. Set on the slave, as openpty(3) does:
    // macOS refuses it on the master (-1, seen in CI).
    let size = libc::winsize {
        ws_row: 24,
        ws_col: 80,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: the slave is open; `size` outlives the call.
    let set = unsafe {
        libc::ioctl(
            slave.as_raw_fd(),
            libc::TIOCSWINSZ,
            &size as *const libc::winsize,
        )
    };
    assert_eq!(set, 0, "TIOCSWINSZ: {}", os_error());
    (master, slave)
}

/// sping with stdout (and stdin, if `keys`) on the pty's `slave`, in a
/// session of its own, so it never reaches the test runner's terminal
/// through /dev/tty.
#[cfg(unix)]
fn sping_on_pty(slave: &std::fs::File, keys: bool, args: &[&str]) -> Child {
    use std::os::unix::process::CommandExt;
    let stdin = if keys {
        Stdio::from(slave.try_clone().unwrap())
    } else {
        Stdio::null()
    };
    let mut cmd = sping_cmd();
    cmd.args(args)
        .stdin(stdin)
        .stdout(Stdio::from(slave.try_clone().unwrap()))
        .stderr(Stdio::null());
    // SAFETY: `setsid` is async-signal-safe, as a `pre_exec` hook must be.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    cmd.spawn().expect("failed to run")
}

/// What sping draws on the pty, read until its slave side closes.
#[cfg(unix)]
fn screen(master: &std::fs::File) -> std::sync::Arc<std::sync::Mutex<Vec<u8>>> {
    let mut master = master.try_clone().unwrap();
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = std::sync::Arc::clone(&seen);
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        // An error (EIO) or 0 once no slave descriptor is open.
        while let Ok(n @ 1..) = master.read(&mut buf) {
            sink.lock().unwrap().extend_from_slice(&buf[..n]);
        }
    });
    seen
}

#[cfg(unix)]
fn wait_until(limit: Duration, mut done: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if done() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    done()
}

/// Whether sping is refused an ICMP socket here, as in a build sandbox (Nix
/// on Linux, GitHub's Ubuntu runner: no unprivileged ICMP, no CAP_NET_RAW).
/// The live views need probes and send their stderr nowhere, so they ask
/// first; only that error skips them, any other failure still fails.
#[cfg(unix)]
fn icmp_denied() -> bool {
    let output = sping_timed(10)
        .args(["127.0.0.1", "-c", "1", "-W", "1", "--view", "classic"])
        .output()
        .expect("failed to run");
    let denied = String::from_utf8_lossy(&output.stderr).contains("failed to create ICMP socket");
    if denied {
        eprintln!("no ICMP permission here: not run");
    }
    denied
}

/// Ctrl+C and `q` quit every live view: compact, extended, `--view table`
/// with one target (it drew in raw mode with no key listener: neither key
/// did anything) and the table of several targets.
#[cfg(unix)]
#[test]
fn test_keys_quit_the_live_views() {
    use std::io::Write;
    if icmp_denied() {
        return;
    }
    let views: [&[&str]; 4] = [
        &["127.0.0.1"],
        &["127.0.0.1", "--view", "extended"],
        &["127.0.0.1", "--view", "table"],
        &["127.0.0.1", "127.0.0.2"],
    ];
    for view in views {
        for key in ["\x03", "q"] {
            let (master, slave) = open_pty();
            let mut child = sping_on_pty(&slave, true, &[view, &["-i", "200"][..]].concat());
            drop(slave);
            let seen = screen(&master);
            // The first frame is drawn in raw mode, with the key listener
            // already started: from then on a key is read as a key.
            let drawn = wait_until(Duration::from_secs(10), || !seen.lock().unwrap().is_empty());
            (&master).write_all(key.as_bytes()).unwrap();
            let quit = drawn
                && wait_until(Duration::from_secs(5), || {
                    matches!(child.try_wait(), Ok(Some(_)))
                });
            if !quit {
                terminate(&mut child).unwrap();
                child.wait().unwrap();
            }
            assert!(drawn, "{view:?}: nothing drawn");
            assert!(quit, "{view:?}: {key:?} did not quit");
            // A normal exit (0, or 1 before every target answered), not a
            // panic or a usage error.
            let status = child.wait().unwrap();
            assert!(matches!(status.code(), Some(0 | 1)), "{view:?}: {status}");
        }
    }
}

/// A live view with no terminal to read keys from (stdin is not one and
/// there is no controlling terminal: cron, systemd, nohup) costs no CPU. The
/// key listener's polls failed at once, and it spun a core.
#[cfg(unix)]
#[test]
fn test_no_terminal_for_keys_does_not_spin() {
    if icmp_denied() {
        return;
    }
    let (master, slave) = open_pty();
    let mut child = sping_on_pty(&slave, false, &["127.0.0.1", "-i", "200"]);
    drop(slave);
    let seen = screen(&master);
    // The live view runs (a sping that stopped at once would cost no CPU
    // either): it drew, and it is still running when measured.
    let drawn = wait_until(Duration::from_secs(10), || !seen.lock().unwrap().is_empty());
    std::thread::sleep(Duration::from_secs(2));
    let running = matches!(child.try_wait(), Ok(None));
    terminate(&mut child).unwrap();
    let pid = child.id() as libc::pid_t;
    let mut status = 0;
    // SAFETY: an all-zero `rusage` is a valid value for `wait4` to fill.
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: `pid` is this test's child, not reaped yet; `status` and
    // `usage` are live for the call.
    let reaped = unsafe { libc::wait4(pid, &mut status, 0, &mut usage) };
    assert_eq!(reaped, pid, "wait4: {}", std::io::Error::last_os_error());
    assert!(drawn, "nothing drawn");
    assert!(running, "sping stopped before the measurement");
    // SIGTERM is a clean shutdown: a normal exit.
    assert!(libc::WIFEXITED(status), "wait status {status:#x}");
    assert!(
        matches!(libc::WEXITSTATUS(status), 0 | 1),
        "exit {}",
        libc::WEXITSTATUS(status)
    );
    let seconds = |t: libc::timeval| t.tv_sec as f64 + t.tv_usec as f64 / 1e6;
    let cpu = seconds(usage.ru_utime) + seconds(usage.ru_stime);
    assert!(cpu < 1.0, "{cpu:.2} s of CPU in 2 s");
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

/// `--icmp` and `--tcp` name two probes: a usage error that names both
/// (not an unknown option, which exits 2 as well).
#[test]
fn test_icmp_and_tcp_are_refused_together() {
    let output = sping_cmd()
        .args(["127.0.0.1", "--icmp", "--tcp", "443", "-c", "1"])
        .output()
        .expect("failed to run");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("cannot be used with")
            && stderr.contains("--icmp")
            && stderr.contains("--tcp"),
        "{stderr}"
    );
}

/// `--icmp` is the probe sping runs without it: the same lines, the same
/// fields, the same exit code. The auxiliary probes' fields (`gateway`,
/// `wan` and the `diagnosis` drawn from them) appear once those probes have
/// a result (JSON_CONTRACT.md), on whichever line that is: not compared.
#[test]
fn test_icmp_is_the_default_probe() {
    // Windows needs no permission for ICMP (`IcmpSendEcho`).
    #[cfg(unix)]
    if icmp_denied() {
        return;
    }
    let keys = |args: &[&str]| {
        let (code, lines, stderr) = json_lines(args, 20);
        assert_eq!(code, Some(0), "{args:?}: {stderr}");
        assert_eq!(lines.len(), 2, "{args:?}: {lines:?}");
        lines
            .iter()
            .map(|l| {
                let mut keys: Vec<String> = l
                    .as_object()
                    .unwrap()
                    .keys()
                    .filter(|k| !["gateway", "wan", "diagnosis"].contains(&k.as_str()))
                    .cloned()
                    .collect();
                keys.sort();
                keys
            })
            .collect::<Vec<_>>()
    };
    let plain = keys(&["127.0.0.1", "-c", "2", "-i", "200"]);
    let icmp = keys(&["127.0.0.1", "-c", "2", "-i", "200", "--icmp"]);
    assert_eq!(icmp, plain);
    assert!(
        icmp.iter().all(|k| !k.iter().any(|k| k == "probe")),
        "{icmp:?}"
    );
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

// === --diagnose ===

#[test]
fn test_diagnose_needs_one_target() {
    let hosts = batch_file("diagnose-batch.txt", "127.0.0.1\n");
    for args in [
        vec!["127.0.0.1", "127.0.0.2", "--diagnose"],
        vec!["--batch", &hosts, "--diagnose"],
    ] {
        let output = sping_cmd().args(&args).output().expect("failed to run");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(2), "{args:?}: {stderr}");
        assert!(
            stderr.contains("--diagnose works with one target"),
            "{stderr}"
        );
    }
}

#[test]
fn test_help_lists_diagnose() {
    let output = sping_cmd().arg("--help").output().expect("failed to run");
    assert!(String::from_utf8_lossy(&output.stdout).contains("--diagnose"));
}

/// Nothing goes down: the lines are those of a run without the flag.
#[test]
fn test_diagnose_says_nothing_while_the_target_answers() {
    let (code, lines, stderr) =
        json_lines(&["127.0.0.1", "--diagnose", "-c", "3", "-i", "200"], 10);
    if lines.is_empty() && stderr.contains("failed to create ICMP socket") {
        eprintln!("no ICMP permission here: not run");
        return;
    }
    // A build sandbox may open the socket and still drop the probes (Nix on
    // Darwin): a whole run with no answer (exit 1, one line per probe) means
    // 127.0.0.1 is down for sping, and this test's premise does not hold.
    // Anything else goes to the checks below.
    if code == Some(1)
        && lines.len() == 3
        && lines
            .iter()
            .all(|l| l["received"] == 0 && l.get("seq").is_some())
    {
        eprintln!("127.0.0.1 does not answer here: not run");
        return;
    }
    assert_eq!(code, Some(0));
    assert_eq!(lines.len(), 3);
    for line in &lines {
        assert!(line.get("active_diagnosis").is_none(), "{line}");
        assert!(line.get("target_ip").is_some() && line.get("seq").is_some());
    }
}

/// `sping ARGS --view json` under the watchdog: its exit code, its lines and
/// what it wrote on stderr.
fn json_lines(args: &[&str], secs: u64) -> (Option<i32>, Vec<serde_json::Value>, String) {
    let mut timed = sping_timed(secs);
    timed.cmd.args(args).args(["--view", "json"]);
    let output = timed.output().expect("failed to run");
    assert!(
        !output.timed_out,
        "sping {args:?} did not finish in {secs} s"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines = stdout
        .lines()
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("invalid JSON '{l}': {e}")))
        .collect();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    (output.status.code(), lines, stderr)
}

/// Run sping and send it SIGTERM after `after`: how long it took to exit
/// once signalled, and what it wrote.
#[cfg(target_os = "linux")]
fn stopped_after(args: &[&str], after: Duration) -> (Duration, String) {
    let mut child = sping_cmd()
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to run");
    let stdout = drain(child.stdout.take());
    let _stderr = drain(child.stderr.take());
    std::thread::sleep(after);
    let signalled = Instant::now();
    terminate(&mut child).expect("cannot signal sping");
    while child.try_wait().expect("cannot wait for sping").is_none() {
        if signalled.elapsed() > Duration::from_secs(10) {
            let _ = child.kill();
            panic!("sping {args:?} still running 10 s after SIGTERM");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let took = signalled.elapsed();
    let stdout = String::from_utf8(stdout.join().expect("stdout reader panicked")).unwrap();
    (took, stdout)
}

/// `--diagnose` against a real path, by case: run by
/// `scripts/diagnose-bench.sh` inside its namespaces (client -> R1 -> R2 ->
/// target, `dual.test` in its hosts file).
#[cfg(target_os = "linux")]
#[test]
#[ignore = "run by scripts/diagnose-bench.sh inside its network namespaces"]
fn diagnose_bench() {
    use serde_json::json;

    let case = std::env::var("SPING_DIAG_CASE").expect("SPING_DIAG_CASE is not set");
    // The last line's diagnosis, once every line was checked: one per
    // probe, none counting an answer, the last one concluded.
    let diagnosed = |args: &[&str]| -> serde_json::Value {
        let mut all = args.to_vec();
        all.extend(["--diagnose", "-c", "3", "-i", "200", "-W", "1"]);
        let (code, lines, _) = json_lines(&all, 90);
        assert_eq!(lines.len(), 3, "{args:?}: {lines:?}");
        assert!(
            lines.iter().all(|l| l["received"] == 0),
            "{args:?}: {lines:?}"
        );
        assert_eq!(code, Some(1), "{args:?}");
        let last = lines[2]["active_diagnosis"].clone();
        assert_eq!(last["state"], "done", "{args:?}: {last}");
        last
    };
    // R2 drops the target before it looks at the TTL: R1 is the last hop
    // that answers.
    let silent_after_r1 = |r1: &str| json!({"code": "silent_after", "last_hop": {"ttl": 1, "from": [r1]}, "silent": 3});
    let ipv6_works =
        json!({"code": "other_family_works", "family": "ipv6", "address": "fd00:3::2"});
    let literal = json!({"about": "other_family", "reason": "literal"});

    match case.as_str() {
        "silent-tail" => {
            for (target, r1) in [("10.0.3.2", "10.0.1.1"), ("fd00:3::2", "fd00:1::1")] {
                let d = diagnosed(&[target]);
                assert_eq!(d["conclusions"], json!([silent_after_r1(r1)]), "{d}");
                assert_eq!(d["gaps"], json!([literal]), "{d}");
                assert_eq!(d["target"], target);
            }
        }
        "prohibited" => {
            for (target, r2) in [("10.0.3.2", "10.0.2.2"), ("fd00:3::2", "fd00:2::2")] {
                let d = diagnosed(&[target]);
                let refused = json!({"code": "reported_unreachable", "ttl": 2, "from": r2, "kind": "admin_prohibited"});
                assert_eq!(d["conclusions"], json!([refused]), "{d}");
            }
        }
        "icmp-ignored" => {
            for target in ["10.0.3.2", "fd00:3::2"] {
                let d = diagnosed(&[target]);
                let refused = json!({"code": "answers_tcp", "port": 443, "refused": true});
                assert_eq!(d["conclusions"], json!([refused]), "{d}");
                assert_eq!(d["gaps"], json!([literal]), "{d}");
            }
        }
        "v4-broken" => {
            let d = diagnosed(&["dual.test"]);
            assert_eq!(
                d["conclusions"],
                json!([silent_after_r1("10.0.1.1"), ipv6_works]),
                "{d}"
            );
            assert_eq!(d["gaps"], json!([]), "{d}");
        }
        "v6-only-host" => {
            let d = diagnosed(&["dual.test"]);
            let no_v4 = json!({"code": "no_source", "family": "ipv4"});
            assert_eq!(d["conclusions"], json!([no_v4, ipv6_works]), "{d}");
        }
        "explicit" => {
            let d = diagnosed(&["dual.test", "-4"]);
            assert_eq!(
                d["conclusions"],
                json!([silent_after_r1("10.0.1.1")]),
                "{d}"
            );
            assert_eq!(
                d["gaps"],
                json!([{"about": "other_family", "reason": "explicit_family"}]),
                "{d}"
            );

            let d = diagnosed(&["dual.test", "-S", "10.0.1.2"]);
            assert_eq!(
                d["conclusions"],
                json!([silent_after_r1("10.0.1.1")]),
                "{d}"
            );
            assert_eq!(
                d["gaps"],
                json!([
                    {"about": "other_family", "reason": "explicit_source"},
                    {"about": "main", "reason": "unknown", "detail": "source check unavailable with -S/-I"},
                ]),
                "{d}"
            );

            // TCP main probe: the other family on that port only (refused:
            // nothing listens), and the trace all the same.
            let d = diagnosed(&["dual.test", "--tcp", "443"]);
            assert_eq!(
                d["conclusions"],
                json!([silent_after_r1("10.0.1.1"), ipv6_works]),
                "{d}"
            );
        }
        "coexist" => {
            for target in ["10.0.3.2", "fd00:3::2"] {
                let d = diagnosed(&[target, "-t", "1"]);
                assert_eq!(
                    d["conclusions"],
                    json!([{"code": "target_answers_icmp", "ttl": 3}]),
                    "{d}"
                );
            }
        }
        "stop" => {
            // In the wait after `-c 3`, during the trace: the held last line
            // says it did not conclude.
            let (took, out) = stopped_after(
                &[
                    "10.0.3.2",
                    "--diagnose",
                    "-c",
                    "3",
                    "-i",
                    "200",
                    "-W",
                    "2",
                    "--view",
                    "json",
                ],
                Duration::from_secs(9),
            );
            assert!(took < Duration::from_secs(3), "{took:?}");
            let lines: Vec<serde_json::Value> = out
                .lines()
                .map(|l| serde_json::from_str(l).unwrap())
                .collect();
            assert_eq!(lines.len(), 3, "{out}");
            assert_eq!(lines[2]["active_diagnosis"]["state"], "incomplete", "{out}");

            // No count, classic, during the trace.
            let (took, out) = stopped_after(
                &[
                    "10.0.3.2",
                    "--diagnose",
                    "-i",
                    "200",
                    "-W",
                    "1",
                    "--view",
                    "classic",
                ],
                Duration::from_secs(5),
            );
            assert!(took < Duration::from_secs(2), "{took:?}");
            assert!(
                out.contains("--- diagnosing why 10.0.3.2 does not answer"),
                "{out}"
            );
            assert!(out.trim_end().ends_with("diagnosis incomplete"), "{out}");
        }
        "context" => context_bench(),
        "renew" => renew_bench(),
        other => panic!("unknown case {other}"),
    }
}

/// The `renew` case of `diagnose_bench`: a long outage
/// (`scripts/diagnose-bench.sh` makes R2 drop the target). A minute in, the
/// first diagnosis long concluded, R2 refuses the target instead: the lines
/// keep the first diagnosis until it is renewed, 5 min after it concluded,
/// and then say what R2 reports, with no context change. Both families at
/// once, one probe a second; the WAN reference is R1, which answers: R2 has
/// no route to the default one, and its errors would spend the client's
/// tokens that R2's refusals need.
#[cfg(target_os = "linux")]
fn renew_bench() {
    use serde_json::{Value, json};

    // `planner::RENEW`, in lines.
    const RENEW_S: usize = 300;
    let run = |target: &'static str| {
        std::thread::spawn(move || {
            let args = [
                target,
                "--diagnose",
                "-c",
                "360",
                "-i",
                "1000",
                "-W",
                "1",
                "--wan-probe",
                "10.0.1.1",
            ];
            let (code, lines, stderr) = json_lines(&args, 420);
            assert_eq!(code, Some(1), "{target}: {stderr}");
            (target, lines)
        })
    };
    let runs = [run("10.0.3.2"), run("fd00:3::2")];
    std::thread::sleep(Duration::from_secs(60));
    for args in [
        ["-4", "route", "replace", "prohibit", "10.0.3.2/32"],
        ["-6", "route", "replace", "prohibit", "fd00:3::2/128"],
    ] {
        let status = Command::new("ip")
            .args(["-n", "r2"])
            .args(args)
            .status()
            .expect("cannot run ip");
        assert!(status.success(), "ip -n r2 {args:?}");
    }

    for ((target, lines), (r1, r2)) in runs
        .map(|r| r.join().unwrap())
        .into_iter()
        .zip([("10.0.1.1", "10.0.2.2"), ("fd00:1::1", "fd00:2::2")])
    {
        assert_eq!(lines.len(), 360, "{target}: {lines:?}");
        assert!(
            lines.iter().all(|l| l["received"] == 0),
            "{target}: {lines:?}"
        );
        assert!(
            lines.iter().all(|l| {
                l["diagnosis"]
                    .as_array()
                    .is_none_or(|findings| findings.iter().all(|f| f["code"] != "context_changed"))
            }),
            "{target}: {lines:?}"
        );
        let conclusions = |line: &Value| line["active_diagnosis"]["conclusions"].clone();
        let first = lines
            .iter()
            .position(|l| l["active_diagnosis"]["state"] == "done")
            .unwrap_or_else(|| panic!("{target}: never concluded: {lines:?}"));
        assert!(first < 50, "{target}: concluded at line {first}");
        assert_eq!(
            conclusions(&lines[first]),
            json!([{"code": "silent_after", "last_hop": {"ttl": 1, "from": [r1]}, "silent": 3}]),
            "{target}"
        );
        // From the first conclusion on, always one: the renewal shows the
        // diagnosis standing until it concludes.
        assert!(
            lines[first..]
                .iter()
                .all(|l| l["active_diagnosis"]["state"] == "done"),
            "{target}: {lines:?}"
        );
        let renewed = first
            + lines[first..]
                .iter()
                .position(|l| conclusions(l) != conclusions(&lines[first]))
                .unwrap_or_else(|| panic!("{target}: never renewed: {lines:?}"));
        println!(
            "{target}: concluded at line {first}, renewed {} lines later",
            renewed - first
        );
        assert!(
            (RENEW_S - 2..=RENEW_S + 25).contains(&(renewed - first)),
            "{target}: renewed {} lines after it concluded",
            renewed - first
        );
        let refused = json!([{"code": "reported_unreachable", "ttl": 2, "from": r2, "kind": "admin_prohibited"}]);
        assert!(
            lines[renewed..].iter().all(|l| conclusions(l) == refused),
            "{target}: {:?}",
            &lines[renewed..]
        );
    }
}

/// The `context` case of `diagnose_bench`: the default route changes during
/// a run (`scripts/diagnose-bench.sh` adds 10.0.1.3 to the client and
/// 10.0.1.254 to R1). The context is re-detected every 15 s: runs of 22
/// probes, one a second, the route changed 3 s in.
#[cfg(target_os = "linux")]
fn context_bench() {
    use serde_json::{Value, json};

    let run = |args: &[&str]| {
        let mut all: Vec<String> = args.iter().map(|a| a.to_string()).collect();
        all.extend(["-c", "22", "-i", "1000", "-W", "1"].map(String::from));
        std::thread::spawn(move || {
            let args: Vec<&str> = all.iter().map(String::as_str).collect();
            let (code, lines, stderr) = json_lines(&args, 60);
            assert_eq!(code, Some(0), "{args:?}: {stderr}");
            (args.join(" "), lines)
        })
    };
    let route = |args: &[&str]| {
        let status = Command::new("ip")
            .args(["route", "replace", "default"])
            .args(args)
            .status()
            .expect("cannot run ip");
        assert!(status.success(), "ip route replace default {args:?}");
    };
    let change_of = |line: &Value| -> Option<Value> {
        line["diagnosis"]
            .as_array()?
            .iter()
            .find(|f| f["code"] == "context_changed")
            .cloned()
    };
    // No line says the context changed.
    let none = |(args, lines): (String, Vec<Value>)| {
        assert_eq!(lines.len(), 22, "{args}: {lines:?}");
        assert!(
            lines.iter().all(|l| change_of(l).is_none()),
            "{args}: {lines:?}"
        );
        lines
    };
    // From the re-detection on, every line says it, older each time; the
    // context of the lines changes with it.
    let changed = |(args, lines): (String, Vec<Value>), changes: Value, ctx: (&str, &str)| {
        assert_eq!(lines.len(), 22, "{args}: {lines:?}");
        let first = lines
            .iter()
            .position(|l| change_of(l).is_some())
            .unwrap_or_else(|| panic!("{args}: no context_changed in {lines:?}"));
        assert!((12..=18).contains(&first), "{args}: first at {first}");
        let mut age = 0;
        for (i, line) in lines.iter().enumerate() {
            let (field, value) = ctx;
            if i < first {
                assert!(change_of(line).is_none(), "{args}: {line}");
                assert_ne!(line["net_ctx"][field], value, "{args}: {line}");
                continue;
            }
            let change = change_of(line).unwrap_or_else(|| panic!("{args}: {line}"));
            assert_eq!(change["changes"], changes, "{args}: {line}");
            let now = change["age_s"].as_u64().unwrap();
            assert!(now >= age && now < 30, "{args}: {line}");
            if i == first {
                assert!(now <= 1, "{args}: {line}");
            }
            age = now;
            assert_eq!(line["net_ctx"][field], value, "{args}: {line}");
        }
    };

    // No change: a re-detection that finds the same context says nothing.
    none(run(&["10.0.3.2"]).join().unwrap());

    // The default route's source changes. With -S or -I the context is the
    // system's route, not the probe's: applied, never reported.
    let runs = [
        run(&["10.0.3.2"]),
        run(&["10.0.3.2", "-S", "10.0.1.2"]),
        run(&["10.0.3.2", "-I", "c0"]),
    ];
    std::thread::sleep(Duration::from_secs(3));
    route(&["via", "10.0.1.1", "src", "10.0.1.3"]);
    let [plain, source, interface] = runs.map(|r| r.join().unwrap());
    route(&["via", "10.0.1.1"]);
    changed(
        plain,
        json!([{"what": "local_ip", "from": "10.0.1.2", "to": "10.0.1.3"}]),
        ("local_ip", "10.0.1.3"),
    );
    for bound in [source, interface] {
        let lines = none(bound);
        assert_eq!(lines[21]["net_ctx"]["local_ip"], "10.0.1.3", "{lines:?}");
    }

    // The default gateway changes.
    let plain = run(&["10.0.3.2"]);
    std::thread::sleep(Duration::from_secs(3));
    route(&["via", "10.0.1.254"]);
    let plain = plain.join().unwrap();
    route(&["via", "10.0.1.1"]);
    changed(
        plain,
        json!([{"what": "gateway", "from": "10.0.1.1", "to": "10.0.1.254"}]),
        ("gateway", "10.0.1.254"),
    );
}

/// The main probe's destination unreachables (step 1 of 1.8): one case per
/// run of `scripts/unreachable-bench.sh` inside its namespaces (client -> R1
/// -> R2 -> target, with RAW sockets and then DGRAM), named by
/// `SPING_UNREACH_CASE`.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "run by scripts/unreachable-bench.sh inside its network namespaces"]
fn unreachable_bench() {
    use serde_json::{Value, json};

    let case = std::env::var("SPING_UNREACH_CASE").expect("SPING_UNREACH_CASE is not set");
    // R2 rate-limits its IPv4 route errors to a host: 5 at once, one more a
    // second (`error_burst`, `error_cost`, which only the initial namespace
    // has). So one probe a second, and R2 itself as the WAN reference: the
    // default one, beyond R2, would spend them.
    const PACE: [&str; 4] = ["-i", "1000", "--wan-probe", "10.0.2.2"];
    let probes = |args: &[&str]| -> Vec<Value> {
        let mut all = args.to_vec();
        all.extend(["-c", "3"]);
        all.extend(PACE);
        let (code, lines, stderr) = json_lines(&all, 30);
        assert_eq!(lines.len(), 3, "{all:?}: {lines:?} {stderr}");
        assert!(
            lines.iter().all(|l| l["received"] == 0),
            "{all:?}: {lines:?}"
        );
        assert_eq!(code, Some(1), "{all:?}: {stderr}");
        lines
    };
    // Every line says who reported the target unreachable, and how.
    let reported = |args: &[&str], from: &str, kind: &str| {
        for line in probes(args) {
            assert_eq!(
                line["icmp_unreachable"],
                json!({"from": from, "kind": kind}),
                "{args:?}: {line}"
            );
        }
    };
    // Classic: each probe's line and the summary, nothing else.
    let classic = |args: &[&str], secs: u64| -> String {
        let mut timed = sping_timed(secs);
        timed.cmd.args(args).args(PACE).args(["--view", "classic"]);
        let output = timed.output().expect("failed to run");
        assert!(!output.timed_out, "sping {args:?} did not finish");
        let out = String::from_utf8_lossy(&output.stdout).into_owned();
        assert_eq!(output.status.code(), Some(1), "{args:?}: {out}");
        assert!(!out.contains("Probe error"), "{args:?}: {out}");
        out
    };
    let silent = |args: &[&str]| {
        for line in probes(args) {
            assert!(line.get("icmp_unreachable").is_none(), "{args:?}: {line}");
        }
    };

    match case.as_str() {
        // R2's `unreachable` route: host unreachable over IPv4, no route
        // (net) over IPv6.
        "unreachable" => {
            reported(&["10.0.3.2", "-W", "2"], "10.0.2.2", "host");
            reported(&["fd00:3::2", "-W", "2"], "fd00:2::2", "net");
            let out = classic(&["10.0.3.2", "-c", "2", "-W", "2"], 20);
            assert_eq!(
                out.lines().take(2).collect::<Vec<_>>(),
                [
                    "From 10.0.2.2: seq=1 Destination Host Unreachable",
                    "From 10.0.2.2: seq=2 Destination Host Unreachable",
                ],
                "{out}"
            );
            assert!(
                out.contains("2 packets transmitted, 0 received, +2 errors, 100.0% packet loss"),
                "{out}"
            );
        }
        "prohibited" => {
            reported(&["10.0.3.2", "-W", "2"], "10.0.2.2", "admin_prohibited");
            reported(&["fd00:3::2", "-W", "2"], "fd00:2::2", "admin_prohibited");
            let out = classic(&["fd00:3::2", "-c", "1", "-W", "2"], 20);
            assert!(
                out.starts_with("From fd00:2::2: seq=1 Packet filtered\n"),
                "{out}"
            );
        }
        // Silence stays a timeout, word for word.
        "blackhole" => {
            silent(&["10.0.3.2", "-W", "1"]);
            silent(&["fd00:3::2", "-W", "1"]);
            let out = classic(&["10.0.3.2", "-c", "2", "-W", "1"], 20);
            assert!(
                out.starts_with("Request timeout for seq=1\nRequest timeout for seq=2\n"),
                "{out}"
            );
            assert!(
                out.contains("2 packets transmitted, 0 received, 100.0% packet loss"),
                "{out}"
            );
        }
        // No neighbor answers on the client's own link: the client says so
        // itself (the bench shortens address resolution to 0.3 s).
        "neighbor" => {
            reported(&["10.0.1.99", "-W", "3"], "10.0.1.2", "host");
            reported(&["fd00:1::99", "-W", "3"], "fd00:1::2", "host");
        }
        // Address resolution takes 3 s, the wait 1 s: every probe's error
        // comes after its wait, some in bursts while later probes are sent.
        // None of them may fail a send or a receive.
        "late" => {
            // A probe sent just before a resolution fails may still get its
            // own error in time: from the client itself.
            for (target, client) in [("10.0.1.98", "10.0.1.2"), ("fd00:1::98", "fd00:1::2")] {
                let out = classic(&[target, "-c", "8", "-W", "1"], 40);
                let lines: Vec<&str> = out.lines().take(8).collect();
                assert!(
                    lines.iter().enumerate().all(|(i, l)| {
                        *l == format!("Request timeout for seq={}", i + 1)
                            || *l
                                == format!(
                                    "From {client}: seq={} Destination Host Unreachable",
                                    i + 1
                                )
                    }),
                    "{out}"
                );
            }
        }
        // R1 sends the client a redirect for every probe (a route back out
        // of the interface the probe came in by): a ping socket gets
        // `EREMOTEIO`. The probes go nowhere: timeouts, never an error.
        "redirect" => {
            silent(&["10.0.3.2", "-W", "1"]);
            let out = classic(&["10.0.3.2", "-c", "3", "-W", "1"], 20);
            assert!(
                out.starts_with(
                    "Request timeout for seq=1\nRequest timeout for seq=2\nRequest timeout for seq=3\n"
                ),
                "{out}"
            );
        }
        // Three processes at once (on RAW sockets every one gets every ICMP
        // error of the host): one probing the unreachable target, one R2,
        // which answers, one diagnosing the target with its traces.
        "crosstalk" => {
            for (target, router, kind) in [
                ("10.0.3.2", "10.0.2.2", "host"),
                ("fd00:3::2", "fd00:2::2", "net"),
            ] {
                let run = |args: &[&str]| {
                    let mut all: Vec<String> = args.iter().map(|a| a.to_string()).collect();
                    all.extend(
                        ["-i", "200", "-W", "1", "--wan-probe", "10.0.2.2"].map(String::from),
                    );
                    std::thread::spawn(move || {
                        let args: Vec<&str> = all.iter().map(String::as_str).collect();
                        json_lines(&args, 60)
                    })
                };
                let down = run(&[target, "-c", "8"]);
                let up = run(&[router, "-c", "8"]);
                let diagnosed = run(&[target, "--diagnose", "-c", "4"]);
                let expected = json!({"from": router, "kind": kind});
                // Over IPv4, R2's rate limit lets only some errors through
                // at this pace: those that came must be right. Over IPv6,
                // every one comes.
                let check = |lines: &[Value]| {
                    let got: Vec<&Value> = lines
                        .iter()
                        .filter_map(|l| l.get("icmp_unreachable"))
                        .collect();
                    assert!(got.iter().all(|u| **u == expected), "{lines:?}");
                    if target.contains(':') {
                        assert_eq!(got.len(), lines.len(), "{lines:?}");
                    } else {
                        assert!(!got.is_empty(), "{lines:?}");
                    }
                };
                let (code, lines, _) = down.join().unwrap();
                assert_eq!((code, lines.len()), (Some(1), 8), "{lines:?}");
                check(&lines);
                let (code, lines, _) = diagnosed.join().unwrap();
                assert_eq!((code, lines.len()), (Some(1), 4), "{lines:?}");
                check(&lines);
                let (code, lines, _) = up.join().unwrap();
                assert_eq!(code, Some(0));
                assert_eq!(lines.len(), 8);
                assert_eq!(lines[7]["received"], 8, "{lines:?}");
                assert!(
                    lines.iter().all(|l| l.get("icmp_unreachable").is_none()),
                    "{lines:?}"
                );
            }
        }
        // A time exceeded (`-t 1`: R1) is not an unreachable: the probe
        // waits for its timeout, as before.
        "ttl1" => {
            silent(&["10.0.3.2", "-t", "1", "-W", "1"]);
            silent(&["fd00:3::2", "-t", "1", "-W", "1"]);
        }
        other => panic!("unknown case {other}"),
    }
}

/// `sping --ip` against a real namespace (step 3 of 1.8): one case per run of
/// `scripts/ip-bench.sh`, which sets up the client of `scripts/bench-net.sh`
/// (`c0`: 10.0.1.2/24, fd00:1::2/64, default routes via R1) and names the
/// case in `SPING_IP_CASE`.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "run by scripts/ip-bench.sh inside its network namespaces"]
fn ip_bench() {
    use serde_json::Value;

    let case = std::env::var("SPING_IP_CASE").expect("SPING_IP_CASE is not set");
    let view = || -> Value {
        let output = sping_timed(10)
            .args(["--ip", "--view", "json"])
            .output()
            .expect("failed to run");
        assert_eq!(output.status.code(), Some(0));
        serde_json::from_str(String::from_utf8_lossy(&output.stdout).trim()).expect("JSON")
    };
    let on = |view: &Value, name: &str| -> Vec<Value> {
        view["interfaces"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|i| i["name"] == name)
            .flat_map(|i| i["addresses"].as_array().unwrap().clone())
            .collect()
    };
    let address = |view: &Value, ip: &str| -> Value {
        on(view, "c0")
            .into_iter()
            .find(|a| a["ip"] == ip)
            .unwrap_or_else(|| panic!("no {ip} on c0: {view}"))
    };
    // Packets sent by every interface of this network namespace:
    // `/proc/net/dev` is the reading process's namespace (`/sys/class/net`
    // is the one sysfs was mounted in, the host's).
    let sent = || -> Vec<(String, u64)> {
        let text = std::fs::read_to_string("/proc/net/dev").unwrap();
        let mut all: Vec<(String, u64)> = text
            .lines()
            .skip(2)
            .map(|line| {
                let (name, counters) = line.split_once(':').unwrap();
                // Receive: bytes packets errs drop fifo frame compressed
                // multicast; then transmit: bytes packets...
                let tx_packets = counters.split_whitespace().nth(9).unwrap().parse().unwrap();
                (name.trim().to_string(), tx_packets)
            })
            .collect();
        all.sort();
        all
    };

    match case.as_str() {
        // A secondary IPv4 address, one with no route, a deprecated IPv6
        // one: all listed, with their prefixes; the sources and the gateway
        // of the default routes; and nothing sent while reading them.
        "addresses" => {
            let before = sent();
            let v = view();
            let _ = sping_timed(10)
                .args(["--ip"])
                .output()
                .expect("failed to run");
            assert_eq!(sent(), before, "--ip sent packets");
            // The control: a real probe to R1 shows on the same counters.
            let _ = sping_timed(10)
                .args(["10.0.1.1", "-c", "1", "--view", "classic"])
                .output()
                .expect("failed to run");
            let after = sent();
            let c0 = |list: &[(String, u64)]| list.iter().find(|(n, _)| n == "c0").unwrap().1;
            assert!(
                c0(&after) > c0(&before),
                "a probe did not show: {before:?} {after:?}"
            );
            for ip in ["10.0.1.2", "10.0.1.9", "10.9.9.9"] {
                let a = address(&v, ip);
                assert_eq!(
                    (a["prefix_len"].as_u64(), a["kind"].as_str()),
                    (Some(24), Some("private")),
                    "{a}"
                );
            }
            let deprecated = address(&v, "fd00:1::d");
            assert_eq!(deprecated["deprecated"], true, "{deprecated}");
            assert_eq!(deprecated["kind"], "private");
            assert_eq!(address(&v, "fd00:1::2")["deprecated"], false);
            assert!(on(&v, "lo").iter().any(|a| a["ip"] == "127.0.0.1"), "{v}");
            assert_eq!(
                v["source"]["ipv4"],
                serde_json::json!({"to": "1.1.1.1", "ip": "10.0.1.2", "interface": "c0"})
            );
            assert_eq!(v["source"]["ipv6"]["ip"], "fd00:1::2", "{v}");
            assert_eq!(
                v["gateway"]["ipv4"],
                serde_json::json!({"ip": "10.0.1.1", "interface": "c0"})
            );
        }
        // Duplicate address detection still running (20 probes).
        "tentative" => {
            let a = address(&view(), "fd00:1::77");
            assert_eq!(
                (a["tentative"].as_bool(), a["duplicate"].as_bool()),
                (Some(true), Some(false)),
                "{a}"
            );
        }
        // R1 holds fd00:1::1: detection found it.
        "duplicate" => {
            let a = address(&view(), "fd00:1::1");
            assert_eq!(a["duplicate"], true, "{a}");
        }
        // The kernel's temporary address for a `mngtmpaddr` prefix.
        "temporary" => {
            let v = view();
            let temporary: Vec<Value> = on(&v, "c0")
                .into_iter()
                .filter(|a| a["temporary"] == true)
                .collect();
            assert_eq!(temporary.len(), 1, "{v}");
            assert!(
                temporary[0]["ip"].as_str().unwrap().starts_with("fd00:5:"),
                "{v}"
            );
            assert_eq!(address(&v, "fd00:5::5")["temporary"], false);
        }
        // No default routes: no source of either family, no gateway.
        "no-default" => {
            let v = view();
            assert_eq!(
                v["source"]["ipv4"],
                serde_json::json!({"to": "1.1.1.1", "ip": null}),
                "{v}"
            );
            assert_eq!(
                v["source"]["ipv6"],
                serde_json::json!({"to": "2606:4700:4700::1111", "ip": null}),
                "{v}"
            );
            assert_eq!(v["gateway"]["ipv4"], Value::Null, "{v}");
            let text = sping_timed(10)
                .args(["--ip"])
                .output()
                .expect("failed to run");
            let text = String::from_utf8_lossy(&text.stdout);
            assert!(text.contains("no IPv4 source to 1.1.1.1"), "{text}");
            assert!(
                text.contains("no IPv6 source to 2606:4700:4700::1111"),
                "{text}"
            );
            assert!(text.contains("no IPv4 default gateway"), "{text}");
        }
        // The bench's STUN server (scripts/stun-bench-server.py, in the
        // target's namespace) answers with addresses of its own after a
        // response of another transaction: the answer is what is said, with
        // the socket each request left from as the server saw it, after one
        // request per family.
        "external" => {
            let (v, elapsed, requests) = external(&["--view", "json"]);
            assert!(elapsed < Duration::from_secs(2), "{elapsed:?}");
            let e = &v["external"];
            assert_eq!(e["server"], "dual.test:3478", "{v}");
            for (family, key, mapped, port, asked, client) in [
                ("v4", "ipv4", "198.51.100.77", 40312, "10.0.3.2", "10.0.1.2"),
                (
                    "v6",
                    "ipv6",
                    "2001:db8:77::5",
                    51022,
                    "fd00:3::2",
                    "fd00:1::2",
                ),
            ] {
                let of_family: Vec<_> = requests.iter().filter(|r| r.0 == family).collect();
                assert_eq!(of_family.len(), 1, "{family}: {requests:?}");
                let (_, source, source_port) = of_family[0];
                assert_eq!(source, client, "{requests:?}");
                let local = std::net::SocketAddr::new(client.parse().unwrap(), *source_port);
                assert_eq!(
                    e[key],
                    serde_json::json!({
                        "ip": mapped, "port": port, "local": local.to_string(), "asked": asked
                    }),
                    "{v}"
                );
            }
            let (text, _, _) = external(&[]);
            let text = text.as_str().unwrap();
            let line = text
                .lines()
                .find(|l| l.starts_with("External "))
                .unwrap_or_else(|| panic!("{text}"));
            assert!(
                line.contains("IPv4 198.51.100.77:40312 from 10.0.1.2:")
                    && line.contains("IPv6 [2001:db8:77::5]:51022 from [fd00:1::2]:")
                    && line.ends_with("(STUN server dual.test:3478)"),
                "{line}"
            );
            assert!(
                !text.contains("203.0.113.9") && !text.contains("2001:db8:99::9"),
                "{text}"
            );
        }
        // Only responses of another transaction (ten a request), or none:
        // unknown at the end of the budget, after three requests per family.
        "external-foreign" | "external-silent" => {
            let (v, elapsed, requests) = external(&["--view", "json"]);
            assert!(
                elapsed >= Duration::from_millis(2900) && elapsed < Duration::from_millis(4500),
                "{elapsed:?}"
            );
            for (family, key, asked) in [("v4", "ipv4", "10.0.3.2"), ("v6", "ipv6", "fd00:3::2")] {
                assert_eq!(
                    v["external"][key],
                    serde_json::json!({"asked": asked, "unknown": "no answer within 3 s"}),
                    "{v}"
                );
                let sent = requests.iter().filter(|r| r.0 == family).count();
                assert_eq!(sent, 3, "{family}: {requests:?}");
            }
        }
        other => panic!("unknown case {other}"),
    }
}

/// One `sping --ip --external dual.test` run with `args`, against the
/// bench's STUN server: the output (JSON, or the text as a string), how
/// long it took, and the requests the server logged (family, source
/// address, source port) during it.
#[cfg(target_os = "linux")]
fn external(args: &[&str]) -> (serde_json::Value, Duration, Vec<(String, String, u16)>) {
    const LOG: &str = "/run/stun-log";
    std::fs::write(LOG, "").expect("empty the STUN server's log");
    let mut cmd = sping_cmd();
    cmd.args(["--ip", "--external", "dual.test"]).args(args);
    let start = Instant::now();
    let output = cmd.output().expect("failed to run");
    let elapsed = start.elapsed();
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let out = if args.contains(&"json") {
        serde_json::from_str(stdout.trim()).expect("JSON")
    } else {
        serde_json::Value::String(stdout)
    };
    let requests = std::fs::read_to_string(LOG)
        .expect("the STUN server's log")
        .lines()
        .map(|line| {
            let fields: Vec<&str> = line.split(' ').collect();
            (
                fields[0].to_string(),
                fields[1].to_string(),
                fields[2].parse().unwrap(),
            )
        })
        .collect();
    (out, elapsed, requests)
}
