#ifndef VM_H
#define VM_H
/*
 * chall7 register VM. Executes the (decrypted) bytecode program that
 * implements the ARX permutation + target comparison. Returns the
 * accumulated difference: 0 means the input maps to the target.
 *
 * Deliberately obfuscated: ARX arithmetic goes through MBA (mixed
 * boolean-arithmetic) identities behind optimizer barriers, opaque
 * predicates guard junk, and the dispatch carries never-emitted decoy
 * opcodes -- so a decompiler/LLM cannot cleanly recover "it's just add/xor".
 *
 * Bounds/iteration guards make a mis-decrypted program (tamper/debugger)
 * reject safely instead of crashing or hanging. ISA mirrors tools/asm.py.
 */

/* volatile opaque-predicate seeds: the optimizer must reload them and so
 * cannot prove the guarded branches are dead. */
static volatile unsigned int g_ov1 = 0x9E3779B9u;
static volatile unsigned int g_ov2 = 0x00000005u;

/* n*(n+1) is always even -> low bit 0 -> false, but opaque to the compiler */
#define OPAQUE_FALSE1 (((g_ov1 * (g_ov1 + 1u)) & 1u) != 0u)
/* n^3 - n is divisible by 3 -> false, opaque */
#define OPAQUE_FALSE2 ((((g_ov2 * g_ov2 * g_ov2) - g_ov2) % 3u) != 0u)

static unsigned int mba_barrier(unsigned int x)
{ __asm__ __volatile__("" : "+r"(x)); return x; }

/* a + b, kept from folding back by a barrier on the split terms */
static unsigned int mba_add(unsigned int a, unsigned int b)
{ unsigned int x = mba_barrier(a ^ b), y = mba_barrier(a & b); return x + (y << 1); }
/* a - b = (a^b) - 2*(~a & b) */
static unsigned int mba_sub(unsigned int a, unsigned int b)
{ unsigned int x = mba_barrier(a ^ b), y = mba_barrier((~a) & b); return x - (y << 1); }
/* a ^ b = (a|b) - (a&b) */
static unsigned int mba_xor(unsigned int a, unsigned int b)
{ unsigned int x = mba_barrier(a | b), y = mba_barrier(a & b); return x - y; }

static unsigned int vm_rotl(unsigned int x, unsigned int r)
{ r &= 31u; return r ? ((x << r) | (x >> (32 - r))) : x; }
static unsigned int vm_rotr(unsigned int x, unsigned int r)
{ r &= 31u; return r ? ((x >> r) | (x << (32 - r))) : x; }

static unsigned int vm_rd32(const unsigned char *p)
{ return (unsigned int)p[0] | ((unsigned int)p[1] << 8)
       | ((unsigned int)p[2] << 16) | ((unsigned int)p[3] << 24); }
static int vm_rd16(const unsigned char *p)   /* signed 16-bit LE */
{ return (int)(short)((unsigned short)p[0] | ((unsigned short)p[1] << 8)); }

static unsigned int vm_execute(const unsigned char *prog, int len,
                               const unsigned int in[8],
                               const unsigned int target[8])
{
    unsigned int R[16];
    unsigned int acc = 0;
    int pc = 0, i;
    long budget = 200000;

    for (i = 0; i < 16; i++) R[i] = 0;

    for (;;) {
        unsigned char op;
        if (pc < 0 || pc >= len) return 0xFFFFFFFFu;
        if (--budget < 0)        return 0xFFFFFFFFu;

        /* opaque junk: never taken, but bloats the decompilation */
        if (OPAQUE_FALSE1) { acc = mba_add(acc, (unsigned int)pc * 0xDEADBEEFu); }

        op = prog[pc++];
        switch (op) {
        case 0x11: { int r = prog[pc] & 15; R[r] = vm_rd32(prog + pc + 1); pc += 5; } break;
        case 0x22: { int r = prog[pc] & 15; R[r] = in[prog[pc + 1] & 7]; pc += 2; } break;
        case 0x33: { int r = prog[pc] & 15; R[r] = target[prog[pc + 1] & 7]; pc += 2; } break;
        case 0x44: R[prog[pc] & 15]  = R[prog[pc + 1] & 15]; pc += 2; break;
        case 0x55: { int a = prog[pc] & 15; R[a] = mba_add(R[a], R[prog[pc + 1] & 15]); pc += 2; } break;
        case 0x66: { int a = prog[pc] & 15; R[a] = mba_sub(R[a], R[prog[pc + 1] & 15]); pc += 2; } break;
        case 0x77: { int a = prog[pc] & 15; R[a] = mba_xor(R[a], R[prog[pc + 1] & 15]); pc += 2; } break;
        case 0x88: R[prog[pc] & 15] *= R[prog[pc + 1] & 15]; pc += 2; break;
        case 0x99: { int r = prog[pc] & 15; R[r] = mba_add(R[r], vm_rd32(prog + pc + 1)); pc += 5; } break;
        case 0xAA: { int r = prog[pc] & 15; R[r] = mba_xor(R[r], vm_rd32(prog + pc + 1)); pc += 5; } break;
        case 0xBB: { int r = prog[pc] & 15; R[r] = vm_rotl(R[r], prog[pc + 1]); pc += 2; } break;
        case 0xCC: { int r = prog[pc] & 15; R[r] = vm_rotr(R[r], prog[pc + 1]); pc += 2; } break;
        case 0xDD: acc |= R[prog[pc] & 15]; pc += 1; break;
        case 0xEE: { int r = prog[pc] & 15; int rel = vm_rd16(prog + pc + 1); pc += 3;
                     if (R[r] != 0) pc += rel; } break;
        case 0xE0: { int r = prog[pc] & 15; int rel = vm_rd16(prog + pc + 1); pc += 3;
                     R[r] = mba_sub(R[r], 1); if (R[r] != 0) pc += rel; } break;
        case 0xF0: { int rel = vm_rd16(prog + pc); pc += 2; pc += rel; } break;
        case 0xFF: return acc;

        /* ---- decoy opcodes: never emitted by the assembler ---- */
        case 0x1A: if (OPAQUE_FALSE2) { R[0] = mba_xor(R[0], 0x1337u); } pc += 2; break;
        case 0x3C: if (OPAQUE_FALSE1) { acc = mba_sub(acc, R[1]); }      pc += 3; break;
        case 0x5E: if (OPAQUE_FALSE2) { R[2] = vm_rotl(R[2], 11); }      pc += 1; break;

        default:   return 0xFFFFFFFFu;
        }

        /* second opaque junk site */
        if (OPAQUE_FALSE2) { R[(pc ^ op) & 15] = mba_add(R[3], 0xCAFEBABEu); }
    }
}

#endif /* VM_H */
