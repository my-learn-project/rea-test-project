//! Local device identity. Neither the protocol nor environment can supply a device ID.
#![forbid(unsafe_code)]

#[cfg(any(windows, test))]
const WINDOWS_DEVICE_DOMAIN: &[u8] = b"card-demo/device/v1\0";

#[cfg(any(windows, target_os = "macos", test))]
fn normalize_uuid(value: &str) -> Option<String> {
    let value = value.trim().to_ascii_lowercase();
    (value.len() == 36
        && value.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        }))
    .then_some(value)
}

#[cfg(any(windows, target_os = "macos", test))]
fn fingerprint(domain: &[u8], uuid: &str) -> String {
    use sha2::{Digest, Sha256};

    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(uuid.as_bytes());
    hash.finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(windows)]
pub(super) fn device_id() -> Result<String, &'static str> {
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY};
    use winreg::RegKey;

    let key = RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey_with_flags(
            "SOFTWARE\\Microsoft\\Cryptography",
            KEY_READ | KEY_WOW64_64KEY,
        )
        .map_err(|_| "无法读取 Windows 设备标识，不能验证设备绑定")?;
    let guid: String = key
        .get_value("MachineGuid")
        .map_err(|_| "Windows MachineGuid 不可用，不能验证设备绑定")?;
    let guid = normalize_uuid(&guid).ok_or("Windows MachineGuid 格式异常，不能验证设备绑定")?;
    // Keep this existing domain and normalization unchanged for issued Windows licenses.
    Ok(fingerprint(WINDOWS_DEVICE_DOMAIN, &guid))
}

#[cfg(any(target_os = "macos", test))]
const MAX_IOREG_OUTPUT: usize = 64 * 1024;

#[cfg(any(target_os = "macos", test))]
const MAC_DEVICE_DOMAIN: &[u8] = b"card-demo/device/macos/v1\0";

#[cfg(any(target_os = "macos", test))]
#[derive(Debug, PartialEq, Eq)]
enum ProbeError {
    Spawn,
    Io,
    OutputLimit,
    Timeout,
    Failed,
    InvalidOutput,
}

#[cfg(any(target_os = "macos", test))]
fn parse_ioreg_uuid(output: &[u8]) -> Result<String, ProbeError> {
    if output.len() > MAX_IOREG_OUTPUT {
        return Err(ProbeError::OutputLimit);
    }
    let text = std::str::from_utf8(output).map_err(|_| ProbeError::InvalidOutput)?;
    let mut uuid = None;
    for line in text.lines() {
        let Some(value) = line.trim().strip_prefix("\"IOPlatformUUID\"") else {
            continue;
        };
        // Ambiguous/multiple platforms and malformed values must never pick a fallback ID.
        if uuid.is_some() {
            return Err(ProbeError::InvalidOutput);
        }
        let value = value
            .trim_start()
            .strip_prefix('=')
            .map(str::trim)
            .and_then(|value| value.strip_prefix('"'))
            .and_then(|value| value.strip_suffix('"'))
            .and_then(normalize_uuid)
            .filter(|value| value != "00000000-0000-0000-0000-000000000000")
            .ok_or(ProbeError::InvalidOutput)?;
        uuid = Some(value);
    }
    uuid.ok_or(ProbeError::InvalidOutput)
}

/// Drain at most `limit + 1` bytes on a separate reader so a full stdout pipe cannot
/// deadlock the parent. The deadline covers both process exit and stdout EOF.
#[cfg(any(target_os = "macos", test))]
fn bounded_command_output(
    mut command: std::process::Command,
    timeout: std::time::Duration,
    limit: usize,
) -> Result<Vec<u8>, ProbeError> {
    use std::io::Read;
    use std::process::{Child, Stdio};
    use std::sync::mpsc::{self, TryRecvError};
    use std::time::{Duration, Instant};

    struct ChildGuard(Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            // Also reap on every error/timeout path; no probe is intentionally left running.
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    let mut child = ChildGuard(
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| ProbeError::Spawn)?,
    );
    let stdout = child.0.stdout.take().ok_or(ProbeError::Io)?;
    let (sender, receiver) = mpsc::channel();
    // A detached reader can only retain its bounded buffer until the killed child closes stdout.
    let _reader = std::thread::Builder::new()
        .name("device-probe-reader".into())
        .spawn(move || {
            let mut output = Vec::with_capacity(limit.min(4096));
            let result = match stdout
                .take(limit.saturating_add(1) as u64)
                .read_to_end(&mut output)
            {
                Err(_) => Err(ProbeError::Io),
                Ok(_) if output.len() > limit => Err(ProbeError::OutputLimit),
                Ok(_) => Ok(output),
            };
            let _ = sender.send(result);
        })
        .map_err(|_| ProbeError::Io)?;
    let started = Instant::now();
    let mut output = None;
    loop {
        if output.is_none() {
            match receiver.try_recv() {
                Ok(result) => output = Some(result?),
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => return Err(ProbeError::Io),
            }
        }
        if let Some(status) = child.0.try_wait().map_err(|_| ProbeError::Io)? {
            if !status.success() {
                return Err(ProbeError::Failed);
            }
            if let Some(output) = output {
                return Ok(output);
            }
        }
        if started.elapsed() >= timeout {
            return Err(ProbeError::Timeout);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(target_os = "macos")]
pub(super) fn device_id() -> Result<String, &'static str> {
    // Apple documents -r/-c to select a matching subtree, -d 1 to exclude children,
    // and -w 0 to disable line clipping. Use the system binary without a shell/PATH lookup.
    // https://github.com/apple-oss-distributions/IOKitTools/blob/main/ioreg.tproj/ioreg.8
    // https://developer.apple.com/documentation/iokit/kioplatformuuidkey
    let mut command = std::process::Command::new("/usr/sbin/ioreg");
    command
        .args(["-r", "-d", "1", "-c", "IOPlatformExpertDevice", "-w", "0"])
        .env_clear()
        .env("LC_ALL", "C");
    let output =
        bounded_command_output(command, std::time::Duration::from_secs(3), MAX_IOREG_OUTPUT)
            .map_err(|_| "无法安全读取 macOS 设备标识，不能验证设备绑定")?;
    let uuid = parse_ioreg_uuid(&output)
        .map_err(|_| "macOS IOPlatformUUID 缺失或格式异常，不能验证设备绑定")?;
    Ok(fingerprint(MAC_DEVICE_DOMAIN, &uuid))
}

#[cfg(not(any(windows, target_os = "macos")))]
pub(super) fn device_id() -> Result<String, &'static str> {
    Err("此演示客户端仅支持 Windows 与 macOS 设备绑定")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::process::Command;
    use std::time::Duration;

    const UUID: &str = "12345678-90ab-cdef-1234-567890abcdef";

    #[test]
    fn ioreg_uuid_parser_normalizes_one_exact_key() {
        let output = b"+-o Mac <class IOPlatformExpertDevice>\n{\n  \"IOPlatformUUID\" = \"12345678-90AB-CDEF-1234-567890ABCDEF\"\n  \"IOPlatformSerialNumber\" = \"irrelevant\"\n}\n";
        assert_eq!(parse_ioreg_uuid(output), Ok(UUID.into()));
    }

    #[test]
    fn ioreg_uuid_parser_rejects_missing_ambiguous_and_malformed_values() {
        for output in [
            "",
            "\"IOPlatformUUID-other\" = \"12345678-90ab-cdef-1234-567890abcdef\"",
            "\"IOPlatformUUID\" = \"00000000-0000-0000-0000-000000000000\"",
            "\"IOPlatformUUID\" = \"not-a-uuid\"",
            "\"IOPlatformUUID\" = \"12345678-90ab-cdef-1234-567890abcdeg\"",
            "\"IOPlatformUUID\" = <12345678-90ab-cdef-1234-567890abcdef>",
            "\"IOPlatformUUID\" = \"12345678-90ab-cdef-1234-567890abcdef\" extra",
            "\"IOPlatformUUID\" = \"12345678-90ab-cdef-1234-567890abcdef\"\n\"IOPlatformUUID\" = \"12345678-90ab-cdef-1234-567890abcdef\"",
        ] {
            assert_eq!(parse_ioreg_uuid(output.as_bytes()), Err(ProbeError::InvalidOutput));
        }
        assert_eq!(parse_ioreg_uuid(&[0xff]), Err(ProbeError::InvalidOutput));
        assert_eq!(
            parse_ioreg_uuid(&vec![b'x'; MAX_IOREG_OUTPUT + 1]),
            Err(ProbeError::OutputLimit)
        );
    }

    #[test]
    fn fingerprints_keep_windows_compatibility_and_separate_platforms() {
        let normalized = normalize_uuid(" 12345678-90AB-CDEF-1234-567890ABCDEF \n").unwrap();
        assert_eq!(
            fingerprint(WINDOWS_DEVICE_DOMAIN, &normalized),
            "21778a2d14a4847707591cad89ab8c1c9bdd9f5534711dfa862c68f571e05501"
        );
        assert_ne!(
            fingerprint(MAC_DEVICE_DOMAIN, UUID),
            fingerprint(WINDOWS_DEVICE_DOMAIN, UUID)
        );
    }

    // The subprocess is this test binary with one exact test selected. This fixture is
    // compiled only for tests and is never a production device/source override.
    #[test]
    fn probe_process_fixture() {
        let Ok(mode) = std::env::var("CARD_DEMO_DEVICE_PROBE_TEST") else {
            return;
        };
        match mode.as_str() {
            "success" => print!("fixture-output"),
            "oversized" => {
                std::io::stdout().write_all(&vec![b'x'; 8192]).unwrap();
            }
            "timeout" => std::thread::sleep(Duration::from_secs(30)),
            "failure" => std::process::exit(7),
            _ => panic!("unknown fixture mode"),
        }
    }

    fn fixture_command(mode: &str) -> Command {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "device::tests::probe_process_fixture",
                "--nocapture",
            ])
            .env("CARD_DEMO_DEVICE_PROBE_TEST", mode);
        command
    }

    #[test]
    fn bounded_probe_reads_output_and_rejects_nonzero_exit() {
        let output =
            bounded_command_output(fixture_command("success"), Duration::from_secs(5), 4096)
                .unwrap();
        assert!(String::from_utf8(output)
            .unwrap()
            .contains("fixture-output"));
        assert_eq!(
            bounded_command_output(fixture_command("failure"), Duration::from_secs(5), 4096),
            Err(ProbeError::Failed)
        );
    }

    #[test]
    fn bounded_probe_limits_output_and_runtime() {
        assert_eq!(
            bounded_command_output(fixture_command("oversized"), Duration::from_secs(5), 1024),
            Err(ProbeError::OutputLimit)
        );
        let started = std::time::Instant::now();
        assert_eq!(
            bounded_command_output(fixture_command("timeout"), Duration::from_millis(100), 4096),
            Err(ProbeError::Timeout)
        );
        assert!(started.elapsed() < Duration::from_secs(5));
    }
}
