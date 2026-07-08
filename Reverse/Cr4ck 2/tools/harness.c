/* Parity harness: proves the C VM (vm.h) matches the Python emulator.
 * Build: gcc -O2 -DVM_HARNESS -I ../src -o harness.exe harness.c            */
#include <stdio.h>
#include <string.h>
#include "vm_program.h"     /* g_prog_plain (VM_HARNESS), g_target_b, PROG_LEN */
#include "vm.h"

static void words(const unsigned char *b, unsigned int w[8])
{
    int i;
    for (i = 0; i < 8; i++)
        w[i] = (unsigned int)b[4*i] | ((unsigned int)b[4*i+1] << 8)
             | ((unsigned int)b[4*i+2] << 16) | ((unsigned int)b[4*i+3] << 24);
}

static unsigned int run(const unsigned char *in32)
{
    unsigned int in[8], target[8];
    words(in32, in);
    words(g_target_b, target);
    return vm_execute(g_prog_plain, PROG_LEN, in, target);
}

int main(void)
{
    unsigned char flag[32], v0[32], v1[32], v2[32], bad[32];
    int i;

    memcpy(flag, "V1rtu4l_ARX_VM_LLM_h3ll_LYKN2026", 32);
    for (i = 0; i < 32; i++) { v0[i] = 0; v1[i] = 0x41; v2[i] = (unsigned char)i; }
    memcpy(bad, flag, 32); bad[5] ^= 1;

    printf("flag  acc = 0x%08X (expect 0)\n", run(flag));
    printf("bad   acc = 0x%08X (expect != 0)\n", run(bad));
    printf("v0    acc = 0x%08X\n", run(v0));
    printf("v1    acc = 0x%08X\n", run(v1));
    printf("v2    acc = 0x%08X\n", run(v2));
    return 0;
}
