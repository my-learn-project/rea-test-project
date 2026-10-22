#ifndef CARDGUARD_AUTHORIZATION_POLICY_H
#define CARDGUARD_AUTHORIZATION_POLICY_H

#include <stdint.h>

enum {
    CARDGUARD_CHECK_RUST_VALID = 1u << 0,
    CARDGUARD_CHECK_VERSION = 1u << 1,
    CARDGUARD_CHECK_PRODUCT = 1u << 2,
    CARDGUARD_CHECK_DEVICE = 1u << 3,
    CARDGUARD_CHECK_FIELDS = 1u << 4,
    CARDGUARD_REQUIRED_CHECKS = 31u
};

#ifdef __cplusplus
extern "C" {
#endif

/* Call only after the in-process Rust verifier has checked the original token.
 * A local policy gate is not a signature verifier or a remote trust boundary. */
int cardguard_policy_allows(uint32_t checks, uint64_t issued_at,
                           uint64_t expires_at, uint64_t now);

#ifdef __cplusplus
}
#endif

#endif
