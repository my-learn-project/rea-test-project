//! Shared license logic used by the standalone CLI and the statically linked Qt application.
#![deny(unsafe_code)]

mod device;
#[allow(unsafe_code)]
mod ffi;

pub use ffi::{cardguard_request, cardguard_run_stdio};

use device::device_id;
use license_core::{parse_public_key, verify};
use serde::Deserialize;
use serde_json::{json, Value};
use std::io::{self, BufRead, Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};

pub const MAX_REQUEST_BYTES: usize = 16 * 1024;
pub const MAX_RESPONSE_BYTES: usize = 64 * 1024;
// Generated before compilation. Runtime file replacement cannot change the trust anchor.
const TRUSTED_KEY: &str = include_str!("../../../config/trusted-public-key.hex");

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    op: Operation,
    #[serde(default)]
    token: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Operation {
    Device,
    Verify,
}

fn error(code: &str, message: &str) -> Value {
    json!({"ok": false, "error": {"code": code, "message": message}})
}

fn handle_request(line: &[u8]) -> Value {
    if line.len() > MAX_REQUEST_BYTES {
        return error("invalid_request", "请求超过 16 KiB 上限");
    }
    let request: Request = match serde_json::from_slice(line) {
        Ok(value) => value,
        Err(_) => return error("invalid_request", "请求必须是规定字段的单行 JSON"),
    };
    match request.op {
        Operation::Device => {
            if request.token.is_some() {
                return error("invalid_request", "获取设备标识时不允许 token 字段");
            }
            match device_id() {
                Ok(id) => json!({"ok": true, "result": {"device_id": id}}),
                Err(message) => error("device_error", message),
            }
        }
        Operation::Verify => {
            let Some(token) = request.token else {
                return error("invalid_request", "验证请求缺少 token 字段");
            };
            let key = match parse_public_key(TRUSTED_KEY) {
                Ok(key) => key,
                Err(e) => return error(e.code(), e.message()),
            };
            let device = match device_id() {
                Ok(device) => device,
                Err(message) => return error("device_error", message),
            };
            let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
                Ok(duration) => duration.as_secs(),
                Err(_) => return error("clock_error", "系统时间无效，无法验证卡密"),
            };
            match verify(&token, &key, &device, now) {
                Ok(license) => json!({"ok": true, "result": license}),
                Err(e) => error(e.code(), e.message()),
            }
        }
    }
}

enum Line {
    Eof,
    TooLong,
    Data(Vec<u8>),
}

fn read_line(reader: &mut impl BufRead) -> io::Result<Line> {
    let mut bytes = Vec::new();
    let n =
        Read::take(&mut *reader, (MAX_REQUEST_BYTES + 1) as u64).read_until(b'\n', &mut bytes)?;
    if n == 0 {
        return Ok(Line::Eof);
    }
    if bytes.len() > MAX_REQUEST_BYTES {
        if bytes.last() != Some(&b'\n') {
            reader.skip_until(b'\n')?;
        }
        return Ok(Line::TooLong);
    }
    Ok(Line::Data(bytes))
}

/// Run the existing bounded JSON-lines protocol for issuance and integration tooling.
pub fn run_stdio() -> io::Result<()> {
    let stdin = io::stdin();
    let mut reader = stdin.lock();
    let stdout = io::stdout();
    let mut writer = stdout.lock();
    loop {
        let response = match read_line(&mut reader)? {
            Line::Eof => break,
            Line::TooLong => error("invalid_request", "请求超过 16 KiB 上限"),
            Line::Data(bytes) => handle_request(&bytes),
        };
        serde_json::to_writer(&mut writer, &response)?;
        writer.write_all(b"\n")?;
        writer.flush()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn rejects_external_device_and_unknown_operation_fields() {
        for request in [
            br#"{"op":"verify","token":"x","device_id":"attacker"}"#.as_slice(),
            br#"{"op":"device","extra":true}"#.as_slice(),
            br#"{"op":"device","token":"x"}"#.as_slice(),
            br#"{"op":"verify"}"#.as_slice(),
            br#"{"op":"verify","token":12}"#.as_slice(),
        ] {
            assert_eq!(handle_request(request)["error"]["code"], "invalid_request");
        }
    }

    #[test]
    fn oversized_line_is_drained_and_next_request_survives() {
        let mut input = vec![b'x'; MAX_REQUEST_BYTES + 100];
        input.extend_from_slice(b"\n{\"op\":\"device\"}\n");
        let mut reader = Cursor::new(input);
        assert!(matches!(read_line(&mut reader).unwrap(), Line::TooLong));
        let Line::Data(next) = read_line(&mut reader).unwrap() else {
            panic!("next request was lost");
        };
        assert_eq!(next, b"{\"op\":\"device\"}\n");
        assert!(matches!(read_line(&mut reader).unwrap(), Line::Eof));
    }
}
