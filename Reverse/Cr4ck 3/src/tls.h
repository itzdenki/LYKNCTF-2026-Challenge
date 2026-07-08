#ifndef TLS_H
#define TLS_H
/*
 * The IV seed is set BEFORE main by a TLS callback (and a CRT constructor as
 * a fallback), so it never appears at the check site. Combined with
 * SHA256(.text), the real IV is derived at runtime, not stored as a constant.
 */
#include <windows.h>

static volatile unsigned int g_tls_seed = 0;

#define TLS_SEED_VALUE 0xB16B00B5u

static void NTAPI lykn_tls_cb(PVOID h, DWORD reason, PVOID res)
{
    (void)h; (void)res;
    if (reason == DLL_PROCESS_ATTACH)
        g_tls_seed = TLS_SEED_VALUE;
}

/* Register the callback in the TLS callback array (.CRT$XLB) and pull in the
 * mingw-w64 TLS support object so the TLS directory is emitted. */
PIMAGE_TLS_CALLBACK lykn_xlb __attribute__((section(".CRT$XLB"), used)) = lykn_tls_cb;
extern char _tls_used;
static const void *lykn_tls_anchor __attribute__((used)) = &_tls_used;

/* Fallback: a pre-main CRT constructor guarantees the seed is set even if the
 * TLS directory is stripped on some toolchains. */
static void __attribute__((constructor)) lykn_seed_ctor(void)
{
    if (g_tls_seed == 0) g_tls_seed = TLS_SEED_VALUE;
}

#endif /* TLS_H */
