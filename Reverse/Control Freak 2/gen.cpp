#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <chrono>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <cerrno>
#include <sys/ptrace.h>
#include <unistd.h>
#endif

#if defined(USE_VMPROTECT)
#include "VMProtectSDK.h"
#else
#define VMProtectBeginUltra(name) ((void)0)
#define VMProtectBeginMutation(name) ((void)0)
#define VMProtectEnd() ((void)0)
#endif

static const std::size_t kInputCap = 127;
static const std::size_t kCipherLen = 30;

// Ciphertext of the flag under the invertible transform below. A reverser can
// read this out of the binary and run the whole pipeline backwards.
static const unsigned char kCipher[kCipherLen] = {
    0xea, 0x43, 0x7a, 0xa1, 0x76, 0x95, 0x48, 0xce, 0xa7, 0xf3, 0x76, 0x07,
    0x9e, 0x82, 0xc8, 0xaa, 0x45, 0x0a, 0x4d, 0x07, 0x84, 0x22, 0x14, 0x7a,
    0x7e, 0x36, 0xa1, 0x59, 0xf4, 0x12,
};

// Constants that drive the transform. All live in the binary.
static const uint64_t kKeyStreamSeed = 0xd1b54a32d192ed03ull;
static const uint64_t kSboxSeed       = 0x9e3779b97f4a7c15ull;
static const unsigned char kChainIV   = 0xa5;

static uint32_t rotl32(uint32_t x, unsigned int r)
{
    r &= 31;
    return r == 0 ? x : (uint32_t)((x << r) | (x >> (32 - r)));
}

static uint64_t rotl64(uint64_t x, unsigned int r)
{
    r &= 63;
    return r == 0 ? x : (uint64_t)((x << r) | (x >> (64 - r)));
}

static unsigned char rotl8(unsigned char x, unsigned int r)
{
    r &= 7u;
    return r == 0 ? x : (unsigned char)(((x << r) | (x >> (8u - r))) & 0xffu);
}

static bool opaque_true(uint32_t x)
{
    volatile uint32_t y = x | 1u;
    return (uint32_t)((y * y) & 1u) == 1u;
}

static bool opaque_false(uint32_t x)
{
    volatile uint32_t y = x;
    return (uint32_t)((y * y + y) & 1u) != 0u;
}

static std::size_t bounded_len(const char *s)
{
    std::size_t n = 0;
    while (n < kInputCap && s[n] != '\0') {
        ++n;
    }
    return n;
}

[[maybe_unused]] static void decode_literal(char *out, const unsigned char *enc, std::size_t n, uint32_t seed)
{
    for (std::size_t i = 0; i < n; ++i) {
        out[i] = (char)(enc[i] ^ ((seed + (uint32_t)i * 29u) & 0xffu));
    }
    out[n] = '\0';
}

#if defined(_WIN32)
static uintptr_t read_peb_addr()
{
#if defined(_WIN64) || defined(__x86_64__)
    uintptr_t peb = 0;
#if defined(_MSC_VER)
    peb = (uintptr_t)__readgsqword(0x60);
#elif defined(__GNUC__)
    __asm__ volatile("movq %%gs:0x60, %0" : "=r"(peb));
#endif
    return peb;
#elif defined(_M_IX86) || defined(__i386__)
    uintptr_t peb = 0;
#if defined(_MSC_VER)
    peb = (uintptr_t)__readfsdword(0x30);
#elif defined(__GNUC__)
    __asm__ volatile("movl %%fs:0x30, %0" : "=r"(peb));
#endif
    return peb;
#else
    return 0;
#endif
}
#endif

static uint32_t timing_probe()
{
    volatile uint64_t spin = 0x9e3779b97f4a7c15ull;
    const auto start = std::chrono::steady_clock::now();
    for (uint32_t i = 0; i < 0x40000u; ++i) {
        spin ^= rotl64(spin + i + 0xd6e8feb86659fd93ull, (i & 31u) + 1u);
        spin *= 0x94d049bb133111ebull;
    }
    const auto stop = std::chrono::steady_clock::now();
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(stop - start).count();
    return elapsed > 750 ? 0x6a09e667u ^ (uint32_t)spin : 0u;
}

static uint32_t anti_probe()
{
    VMProtectBeginUltra(nullptr);

    uint32_t poison = timing_probe();

#if defined(_WIN32)
    if (IsDebuggerPresent()) {
        poison ^= 0xbb67ae85u;
    }

    BOOL remote = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote) && remote) {
        poison ^= 0x3c6ef372u;
    }

    const uintptr_t peb = read_peb_addr();
    if (peb != 0) {
        const unsigned char *p = (const unsigned char *)peb;
        if (p[2] != 0) {
            poison ^= 0xa54ff53au;
        }
        uint32_t nt_global_flag = 0;
#if defined(_WIN64) || defined(__x86_64__)
        std::memcpy(&nt_global_flag, p + 0xbc, sizeof(nt_global_flag));
#elif defined(_M_IX86) || defined(__i386__)
        std::memcpy(&nt_global_flag, p + 0x68, sizeof(nt_global_flag));
#endif
        if ((nt_global_flag & 0x70u) != 0) {
            poison ^= 0x510e527fu;
        }
    }

#if defined(_M_X64) || defined(__x86_64__) || defined(_M_IX86) || defined(__i386__)
    CONTEXT ctx;
    std::memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0 || ctx.Dr7 != 0) {
            poison ^= 0x9b05688cu;
        }
    }
#endif
#else
    bool saw_status = false;
    bool traced = false;
    const unsigned char proc_status_enc[] = {
        0x72, 0x0a, 0xe5, 0xdb, 0xb2, 0xc1, 0x78, 0x4d, 0x29,
        0x04, 0x50, 0xef, 0xcd, 0xb7, 0x87, 0x65, 0x5e
    };
    const unsigned char tracer_enc[] = {
        0x65, 0x3c, 0x0a, 0xeb, 0xc0, 0xb0, 0x8f, 0x95, 0x7d, 0x0c
    };
    char proc_status[sizeof(proc_status_enc) + 1];
    char tracer_key[sizeof(tracer_enc) + 1];
    decode_literal(proc_status, proc_status_enc, sizeof(proc_status_enc), 0x5du);
    decode_literal(tracer_key, tracer_enc, sizeof(tracer_enc), 0x31u);

    FILE *status = std::fopen(proc_status, "rb");
    if (status != NULL) {
        char line[160];
        while (std::fgets(line, sizeof(line), status) != NULL) {
            if (std::memcmp(line, tracer_key, sizeof(tracer_enc)) == 0) {
                saw_status = true;
                if (std::atoi(line + 10) != 0) {
                    traced = true;
                    poison ^= 0xbb67ae85u;
                }
                break;
            }
        }
        std::fclose(status);
    }

    errno = 0;
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1 && errno == EPERM && (!saw_status || traced)) {
        poison ^= 0x3c6ef372u;
    }

    const unsigned char preload_enc[] = {
        0x2b, 0xc0, 0xfe, 0xee, 0x89, 0xbd, 0x59, 0x7d, 0x0e, 0x28
    };
    const unsigned char audit_enc[] = {
        0x6f, 0x04, 0x02, 0x3b, 0xc2, 0xf0, 0x98, 0xba
    };
    char preload_key[sizeof(preload_enc) + 1];
    char audit_key[sizeof(audit_enc) + 1];
    decode_literal(preload_key, preload_enc, sizeof(preload_enc), 0x67u);
    decode_literal(audit_key, audit_enc, sizeof(audit_enc), 0x23u);

    if (std::getenv(preload_key) != NULL || std::getenv(audit_key) != NULL) {
        poison ^= 0xa54ff53au;
    }
#endif

    VMProtectEnd();
    return poison;
}

// splitmix64: the PRNG behind both the keystream and the S-box schedule.
static uint64_t splitmix64(uint64_t *state)
{
    *state += 0x9e3779b97f4a7c15ull;
    uint64_t z = *state;
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;
    return z ^ (z >> 31);
}

// Fisher-Yates shuffle of 0..255 seeded by kSboxSeed -> an invertible S-box.
static void build_sbox(unsigned char sbox[256])
{
    for (int i = 0; i < 256; ++i) {
        sbox[i] = (unsigned char)i;
    }
    uint64_t state = kSboxSeed;
    for (int i = 255; i > 0; --i) {
        const uint64_t z = splitmix64(&state);
        const int j = (int)(z % (uint64_t)(i + 1));
        const unsigned char t = sbox[i];
        sbox[i] = sbox[j];
        sbox[j] = t;
    }
}

// Invertible per-byte transform with CBC-style chaining. Every step (keystream
// xor, position add, byte rotate, S-box, chain xor) has an exact inverse, so
// the flag is fully recoverable from kCipher.
static void transform(const unsigned char *input, std::size_t len, uint32_t poison,
                      unsigned char out[kCipherLen])
{
    VMProtectBeginUltra(nullptr);

    unsigned char sbox[256];
    build_sbox(sbox);

    uint64_t ks = kKeyStreamSeed ^ ((uint64_t)poison * 0x100000001b3ull);
    unsigned char prev = kChainIV;
    for (uint32_t i = 0; i < kCipherLen; ++i) {
        const unsigned char k = (unsigned char)(splitmix64(&ks) & 0xffu);
        const unsigned char ch = (i < len) ? input[i] : (unsigned char)0;
        unsigned char t = (unsigned char)(ch ^ k);
        t = (unsigned char)(t + (unsigned char)(i * 37u + 0x5au));
        t = rotl8(t, i & 7u);
        t = sbox[t];
        t = (unsigned char)(t ^ prev);
        out[i] = t;
        prev = t;
    }

    VMProtectEnd();
}

static void fake_path(uint32_t seed, unsigned char scratch[kCipherLen])
{
    VMProtectBeginMutation(nullptr);

    uint64_t x = 0x6a09e667f3bcc909ull ^ seed;
    for (uint32_t i = 0; i < kCipherLen; ++i) {
        x ^= rotl64(x + scratch[i] + i, (i & 15u) + 5u);
        scratch[i] = (unsigned char)(scratch[i] ^ (x >> ((i & 7u) * 8u)));
    }

    VMProtectEnd();
}

static bool guarded_check(const char *input)
{
    unsigned char cipher[kCipherLen] = {0};
    unsigned char expected[kCipherLen] = {0};
    std::size_t len = 0;
    uint32_t poison = 0;
    uint32_t diff = 1;
    uint32_t seed = 0x7f4a7c15u;
    bool done = false;
    volatile uint32_t pc = 0x91cf3a2bu;

    for (uint32_t turns = 0; !done && turns < 16; ++turns) {
        switch (pc) {
        case 0x91cf3a2bu:
            poison = anti_probe();
            seed ^= rotl32(poison + 0x243f6a88u, 7);
            pc = opaque_true(seed) ? 0xd2387a55u : 0x104c11dbu;
            break;

        case 0xd2387a55u:
            len = bounded_len(input);
            seed += (uint32_t)(len * 0x45d9f3bu);
            pc = opaque_true(seed ^ (uint32_t)len) ? 0x0f6d3c2au : 0x661c23f1u;
            break;

        case 0x0f6d3c2au:
            transform((const unsigned char *)input, len, poison, cipher);
            seed ^= (uint32_t)(cipher[0] | (cipher[1] << 8));
            if (opaque_false(seed)) {
                fake_path(seed, cipher);
            }
            pc = 0x58a91e43u;
            break;

        case 0x58a91e43u:
            std::memcpy(expected, kCipher, kCipherLen);
            if (opaque_false(seed ^ 0x9e3779b9u)) {
                fake_path(seed ^ 0xa5a5a5a5u, expected);
            }
            pc = 0xaf314621u;
            break;

        case 0xaf314621u:
            diff = (len == kCipherLen) ? 0u : 1u;
            for (uint32_t i = 0; i < kCipherLen; ++i) {
                const uint32_t j = (i * 7u + 11u) % kCipherLen;
                diff |= (uint32_t)(cipher[j] ^ expected[j]);
            }
            diff |= (poison | (poison >> 8) | (poison >> 16) | (poison >> 24)) & 0xffu;
            pc = 0x3d12f0b7u;
            break;

        case 0x3d12f0b7u:
            done = true;
            break;

        default:
            diff |= 0xffffffffu;
            done = true;
            break;
        }
    }

    return diff == 0;
}

int main(int argc, char **argv)
{
    char input[128];

    if (argc > 1) {
        std::strncpy(input, argv[1], sizeof(input) - 1);
        input[sizeof(input) - 1] = '\0';
    } else {
        std::printf("flag: ");
        if (std::fgets(input, sizeof(input), stdin) == NULL) {
            return 1;
        }
        input[std::strcspn(input, "\r\n")] = '\0';
    }

    const bool ok = guarded_check(input);
    std::puts(ok ? "Correct!" : "Nope");
    return ok ? 0 : 1;
}
