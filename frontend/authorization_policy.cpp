#include "authorization_policy.h"

/* This translation unit alone is compiled by the pinned xollvm toolchain.
 * The release build must inspect xollvm's report: annotations alone do not
 * prove that a transform ran. Keep the crypto implementation unmodified.
 * No anti-debugging, timing traps, executable packing or library restrictions.
 */
#if defined(__clang__) && defined(CARDGUARD_XOLLVM)
#define CARDGUARD_POLICY_PROTECTION \
    __attribute__((annotate("obf: vm(antiDebug=0,bindAntiDebug=0)"), noinline))
#elif defined(_MSC_VER)
#define CARDGUARD_POLICY_PROTECTION __declspec(noinline)
#else
#define CARDGUARD_POLICY_PROTECTION __attribute__((noinline))
#endif

extern "C" CARDGUARD_POLICY_PROTECTION
int cardguard_policy_allows(uint32_t checks, uint64_t issued_at,
                           uint64_t expires_at, uint64_t now)
{
    /* One value-returning exit is intentional: xollvm v0.11.1 excludes
     * functions with multiple value-returning returns from VM conversion. */
    int allowed = 0;
    if (checks == CARDGUARD_REQUIRED_CHECKS) {
        if (issued_at > UINT64_C(0) && issued_at <= now && now < expires_at) {
            if (expires_at < UINT64_C(253402300800)
                && expires_at - issued_at <= UINT64_C(31622400)) {
                allowed = 1;
            }
        }
    }
    return allowed;
}
