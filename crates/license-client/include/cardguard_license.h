#ifndef CARDGUARD_LICENSE_H
#define CARDGUARD_LICENSE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CARDGUARD_MAX_REQUEST_BYTES = 16 * 1024,
    CARDGUARD_MAX_RESPONSE_BYTES = 64 * 1024
};

/*
 * Process one JSON request in the application process. Rust reads the platform
 * identity, current time and compiled trust anchor; callers cannot override them.
 *
 * request_len must be 1..CARDGUARD_MAX_REQUEST_BYTES; output_capacity must be
 * 1..CARDGUARD_MAX_RESPONSE_BYTES. Supply separate, live, non-overlapping buffers
 * valid for the stated sizes, without concurrent conflicting access. No pointer
 * is retained. Nulls, invalid lengths and overlapping ranges are rejected.
 *
 * Return: UTF-8 JSON byte length, without NUL/newline. License rejection returns
 * JSON with ok:false. Zero means ABI/capacity/internal failure and output must be
 * ignored. The caller must reject zero, malformed responses and ok:false.
 * Unwinding Rust panics are contained; release panic=abort terminates the process.
 */
size_t cardguard_request(const uint8_t *request, size_t request_len,
                         uint8_t *output, size_t output_capacity);

/*
 * Exclusive diagnostic entry point using the process's standard handles. Call
 * before creating a GUI or any other reader/writer on stdin/stdout. Runs the
 * same bounded JSON-lines protocol as the standalone Rust CLI until stdin EOF.
 * Returns 0 on normal completion and 1 on I/O or contained unwinding failure.
 */
int cardguard_run_stdio(void);

#ifdef __cplusplus
}
#endif

#endif
