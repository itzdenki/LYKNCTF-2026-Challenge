/* In-process proof: (1) the real flag passes (C MIX == Python CHK), and
 * (2) the flag is recoverable byte-by-byte using ONLY run_check as an oracle.
 * Build: gcc -O2 -DCHECK_HARNESS -I ../src -o harness.exe harness.c          */
#include <stdio.h>
#include <string.h>
#include "mix.h"
#include "vm8.h"            /* run_check_vm, vm_mix + check_data.h */

int main(void)
{
    unsigned char cand[CHECK_N];
    int i, c, best, bestp, p;
    unsigned int s;

    /* 0) VM parity: vm_mix must equal the reference MIX on random triples */
    s = 0x12345678u;
    for (i = 0; i < 5000; i++) {
        unsigned int st = s * 2654435761u + 1u, cc = (s >> 3) & 0xFF, rc = s ^ 0xDEAD;
        if (vm_mix(st, cc, rc) != MIX(st, cc, rc)) { printf("VM PARITY FAIL at %d\n", i); return 1; }
        s = st;
    }
    printf("VM parity (vm_mix == MIX) OK over 5000 triples\n");

    /* 1) real flag passes fully (through the VM) */
    p = run_check_vm(g_inner, CHECK_N, CHECK_IV, g_chk);
    printf("flag run_check_vm = %d (expect %d)\n", p, CHECK_N);

    /* 2) byte-by-byte oracle solve (no peeking at g_inner) */
    memset(cand, '?', sizeof(cand));
    for (i = 0; i < CHECK_N; i++) {
        best = -1; bestp = i;
        for (c = 0x20; c <= 0x7E; c++) {
            cand[i] = (unsigned char)c;
            p = run_check_vm(cand, CHECK_N, CHECK_IV, g_chk);
            if (p > bestp) { bestp = p; best = c; }
        }
        if (best < 0) { printf("stuck at %d\n", i); return 1; }
        cand[i] = (unsigned char)best;
    }

    printf("recovered inner = LYKNCTF{%.*s}\n", CHECK_N, cand);
    printf("matches flag    = %s\n",
           memcmp(cand, g_inner, CHECK_N) == 0 ? "YES" : "NO");
    return 0;
}
