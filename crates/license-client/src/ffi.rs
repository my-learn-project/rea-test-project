//! The only unsafe module: two pointer operations at the bounded C ABI boundary.
//! See include/cardguard_license.h for the caller contract. All license logic is safe Rust.

use crate::{handle_request, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES};
use std::panic::{catch_unwind, UnwindSafe};

fn contain_panic(operation: impl FnOnce() -> usize + UnwindSafe) -> usize {
    // Unwind builds fail closed. With the release panic=abort profile the process terminates;
    // neither mode permits a Rust panic to unwind through a C++ stack frame.
    catch_unwind(operation).unwrap_or(0)
}

/// Run the bounded JSON-lines diagnostic protocol on the process's standard handles.
/// Call only from an exclusive diagnostic entry point before starting a GUI or other
/// reader/writer of those handles. Normal EOF returns 0; I/O or unwinding failure
/// returns 1. With panic=abort, a panic terminates the process instead of unwinding.
#[no_mangle]
pub extern "C" fn cardguard_run_stdio() -> std::ffi::c_int {
    match catch_unwind(crate::run_stdio) {
        Ok(Ok(())) => 0,
        _ => 1,
    }
}

/// Process one JSON request using Rust's own device ID, clock and compiled public key.
/// Returns the UTF-8 JSON byte count, without a trailing NUL or newline, or 0 for an ABI,
/// capacity, serialization or internal failure. An invalid license returns nonzero JSON
/// containing `ok:false`; callers must inspect that field before granting access.
///
/// # Safety
/// Nulls, invalid lengths, address overflow and overlapping ranges are rejected without
/// dereferencing either pointer. For a call not rejected by those checks, `request`
/// must be readable and initialized
/// for `request_len` bytes in a single allocation, and `output` must be writable for
/// `output_capacity` bytes in a single allocation. Both allocations must remain live for
/// the call, must not overlap, and must not be concurrently modified/accessed in conflict
/// with these reads/writes. Capacity must describe actual allocated memory. Arbitrary
/// dangling pointers cannot be validated by this API. No pointers are retained.
#[no_mangle]
pub unsafe extern "C" fn cardguard_request(
    request: *const u8,
    request_len: usize,
    output: *mut u8,
    output_capacity: usize,
) -> usize {
    if request.is_null()
        || output.is_null()
        || request_len == 0
        || request_len > MAX_REQUEST_BYTES
        || output_capacity == 0
        || output_capacity > MAX_RESPONSE_BYTES
    {
        return 0;
    }
    let request_start = request as usize;
    let output_start = output as usize;
    let (Some(request_end), Some(output_end)) = (
        request_start.checked_add(request_len),
        output_start.checked_add(output_capacity),
    ) else {
        return 0;
    };
    if request_start < output_end && output_start < request_end {
        return 0;
    }
    contain_panic(|| {
        // SAFETY: Non-null, bounded length and address arithmetic were checked above.
        // The caller promises initialized readable memory in one live allocation,
        // with no conflicting mutation. This slice does not escape the call.
        let request = unsafe { std::slice::from_raw_parts(request, request_len) };
        let Ok(response) = serde_json::to_vec(&handle_request(request)) else {
            return 0;
        };
        if response.is_empty()
            || response.len() > output_capacity
            || response.len() > MAX_RESPONSE_BYTES
        {
            return 0;
        }
        // SAFETY: The caller promises writable output_capacity bytes. The check above
        // proves the response fits. Its Vec owns a separate initialized allocation;
        // it cannot overlap the caller's live output allocation. u8 alignment is 1.
        unsafe { std::ptr::copy_nonoverlapping(response.as_ptr(), output, response.len()) };
        response.len()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn ffi_returns_bounded_json_without_a_terminator_or_overwriting_tail() {
        let request = br#"{"op":"verify","token":"x","device_id":"injected"}"#;
        let mut output = [0xa5; MAX_RESPONSE_BYTES];
        // SAFETY: Distinct live arrays satisfy the documented read/write contract.
        let n = unsafe {
            cardguard_request(
                request.as_ptr(),
                request.len(),
                output.as_mut_ptr(),
                output.len(),
            )
        };
        assert!(n > 0 && n < output.len());
        let response: Value = serde_json::from_slice(&output[..n]).unwrap();
        assert_eq!(response["ok"], false);
        assert_eq!(response["error"]["code"], "invalid_request");
        assert!(output[n..].iter().all(|&byte| byte == 0xa5));
        assert_ne!(output[n - 1], b'\n');
    }

    #[test]
    fn ffi_rejects_small_output_without_partial_writes() {
        let request = b"{}";
        let mut output = [0xa5; 1];
        // SAFETY: Both pointers reference distinct, valid arrays with exact lengths.
        let n = unsafe {
            cardguard_request(
                request.as_ptr(),
                request.len(),
                output.as_mut_ptr(),
                output.len(),
            )
        };
        assert_eq!(n, 0);
        assert_eq!(output, [0xa5]);
    }

    #[test]
    fn ffi_rejects_null_empty_oversized_and_overlapping_buffers() {
        let request = [b' '; MAX_REQUEST_BYTES + 1];
        let mut output = [0xa5; MAX_RESPONSE_BYTES + 1];
        // SAFETY: These arrays are valid for every non-null range below. Invalid
        // lengths/null pointers are rejected before dereferencing either pointer.
        unsafe {
            assert_eq!(
                cardguard_request(std::ptr::null(), 1, output.as_mut_ptr(), 32),
                0
            );
            assert_eq!(
                cardguard_request(request.as_ptr(), 1, std::ptr::null_mut(), 32),
                0
            );
            assert_eq!(
                cardguard_request(request.as_ptr(), 0, output.as_mut_ptr(), 32),
                0
            );
            assert_eq!(
                cardguard_request(request.as_ptr(), request.len(), output.as_mut_ptr(), 32),
                0
            );
            assert_eq!(
                cardguard_request(request.as_ptr(), 1, output.as_mut_ptr(), 0),
                0
            );
            assert_eq!(
                cardguard_request(request.as_ptr(), 1, output.as_mut_ptr(), output.len()),
                0
            );
            let same = output.as_mut_ptr();
            assert_eq!(cardguard_request(same, 2, same, 32), 0);
        }
        assert!(output.iter().all(|&byte| byte == 0xa5));
    }

    #[test]
    fn ffi_accepts_exact_request_and_output_limits() {
        let mut request = vec![b' '; MAX_REQUEST_BYTES];
        request[..2].copy_from_slice(b"{}");
        let mut output = vec![0; MAX_RESPONSE_BYTES];
        // SAFETY: Distinct buffers are valid for their exact lengths.
        let n = unsafe {
            cardguard_request(
                request.as_ptr(),
                request.len(),
                output.as_mut_ptr(),
                output.len(),
            )
        };
        assert!(n > 0);
        let response: Value = serde_json::from_slice(&output[..n]).unwrap();
        assert_eq!(response["error"]["code"], "invalid_request");
    }

    #[cfg(panic = "unwind")]
    #[test]
    fn unwinding_panics_fail_closed() {
        assert_eq!(contain_panic(|| panic!("test boundary panic")), 0);
    }
}
