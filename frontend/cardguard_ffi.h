#ifndef CARDGUARD_FFI_H
#define CARDGUARD_FFI_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Executes one UTF-8 JSON request inside the statically linked Rust verifier.
 * Request length: 1..16384 bytes. Output capacity: 1..65536 bytes.
 * Returns bytes written, without a trailing NUL, or zero on an ABI/internal error.
 * A rejected license is a nonzero JSON response with "ok": false.
 * The caller owns both buffers and keeps them valid for the entire call.
 */
size_t cardguard_request(const uint8_t *request, size_t request_len,
                         uint8_t *output, size_t output_capacity);

/* Run the bounded diagnostic JSON-lines protocol on stdin/stdout without Qt.
 * Returns 0 on normal EOF, or 1 on I/O/internal failure. */
int cardguard_run_stdio(void);

#ifdef __cplusplus
}
#endif

#endif
