#include "authorization_policy.h"
#include <cstdint>
#include <cstdio>
#include <limits>

int main()
{
    struct Case { uint32_t checks; uint64_t issued; uint64_t expiry; uint64_t now; int expected; };
    const Case cases[] = {
        {31, 1000, 2000, 1000, 1}, {31, 1000, 2000, 1999, 1},
        {31, 1000, 2000, 2000, 0}, {31, 1000, 2000, 999, 0},
        {31, 0, 2000, 1000, 0}, {31, 1000, 1000, 1000, 0},
        {31, 2000, 1000, 1500, 0}, {31, 1, 31622401, 1, 1},
        {31, 1, 31622402, 1, 0}, {31, 253402300798ULL, 253402300799ULL, 253402300798ULL, 1},
        {31, 253402300799ULL, 253402300800ULL, 253402300799ULL, 0},
        {31, 1000, UINT64_MAX, 1000, 0}, {31, 1000, 2000, UINT64_MAX, 0},
        {UINT32_MAX, 1000, 2000, 1500, 0}
    };
    unsigned count = 0;
    for (const auto &item : cases) {
        if (cardguard_policy_allows(item.checks, item.issued, item.expiry, item.now) != item.expected) {
            std::fprintf(stderr, "Policy boundary case %u failed\n", count);
            return 1;
        }
        ++count;
    }
    for (uint32_t flags = 0; flags < 64; ++flags) {
        if (cardguard_policy_allows(flags, 1000, 2000, 1500) != (flags == 31 ? 1 : 0)) {
            std::fprintf(stderr, "Policy permission combination failed\n");
            return 1;
        }
        ++count;
    }
    // Deterministic differential checks cover the VM's 64-bit arithmetic and comparisons.
    uint64_t state = 0x968d42a9cb731e5ULL;
    auto random = [&state]() { state ^= state << 13; state ^= state >> 7; state ^= state << 17; return state; };
    for (unsigned i = 0; i < 4096; ++i) {
        const uint32_t flags = i % 3 == 0 ? 31 : static_cast<uint32_t>(random() & 63);
        const uint64_t issued = random() % 253402300810ULL;
        const uint64_t expiry = i % 2 == 0 ? issued + (random() % 31622410ULL) : random();
        const uint64_t now = i % 4 == 0 ? issued : issued + (random() % 31622410ULL);
        const bool expected = flags == 31 && issued > 0 && expiry < 253402300800ULL
            && issued <= now && now < expiry && expiry > issued && expiry - issued <= 31622400ULL;
        if (cardguard_policy_allows(flags, issued, expiry, now) != (expected ? 1 : 0)) {
            std::fprintf(stderr, "Policy differential case %u failed\n", i);
            return 1;
        }
        ++count;
    }
    std::printf("PASS: %u virtualized policy boundary, permission and differential cases\n", count);
    return 0;
}
