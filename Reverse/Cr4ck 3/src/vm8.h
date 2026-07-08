#ifndef VM8_H
#define VM8_H
/*
 * chall8 register VM that computes MIX. The bytecode (g_code_enc) is stored
 * under a self-synchronizing stream cipher keyed on PLAINTEXT history: to
 * decrypt instruction/byte j you must have already decrypted 0..j-1. So the
 * program cannot be laid out statically without emulating the whole chain --
 * there is no moment where the full cleartext program exists in memory.
 *
 * MIX is straight-line (no jumps), so the fetch order is fixed and the chain
 * reproduces exactly, independent of the input.
 *
 * ISA / chain mirror tools/gen.py.
 */
#include "check_data.h"    /* g_code_enc, CODE_LEN, VM_SEED */

static unsigned int v8_rotl(unsigned int x, int r)
{ return (x << r) | (x >> (32 - r)); }

/* --- light obfuscation: MBA behind optimizer barriers + opaque predicates,
 * so a decompiler cannot cleanly show the MIX arithmetic as add/xor. --- */
static volatile unsigned int g8_ov1 = 0x9C5AB3D7u, g8_ov2 = 7u;
#define O8_FALSE1 (((g8_ov1 * (g8_ov1 + 1u)) & 1u) != 0u)
#define O8_FALSE2 ((((g8_ov2 * g8_ov2 * g8_ov2) - g8_ov2) % 3u) != 0u)
static unsigned int m8_bar(unsigned int x) { __asm__ __volatile__("" : "+r"(x)); return x; }
static unsigned int m8_add(unsigned int a, unsigned int b)
{ unsigned int x = m8_bar(a ^ b), y = m8_bar(a & b); return x + (y << 1); }
static unsigned int m8_sub(unsigned int a, unsigned int b)
{ unsigned int x = m8_bar(a ^ b), y = m8_bar((~a) & b); return x - (y << 1); }
static unsigned int m8_xor(unsigned int a, unsigned int b)
{ unsigned int x = m8_bar(a | b), y = m8_bar(a & b); return x - y; }

/* fetch one plaintext byte, advancing the rolling key with the plaintext */
static unsigned char v8_fetch(unsigned int *ks, int *pc)
{
    unsigned char mask = (unsigned char)((*ks >> 24) & 0xFF);
    unsigned char b = (unsigned char)(g_code_enc[*pc] ^ mask);
    *ks = v8_rotl(*ks ^ b, 11) * 0x9C5AB3D7u + 0x3F1E5C2Bu;
    (*pc)++;
    return b;
}
static unsigned int v8_fetch32(unsigned int *ks, int *pc)
{
    unsigned int v = 0; int k;
    for (k = 0; k < 4; k++) v |= (unsigned int)v8_fetch(ks, pc) << (8 * k);
    return v;
}

static unsigned int vm_mix(unsigned int state, unsigned int c, unsigned int rc)
{
    unsigned int R[8];
    unsigned int ks = VM_SEED;
    unsigned int out = 0;
    int pc = 0, i;
    long budget = 100000;

    for (i = 0; i < 8; i++) R[i] = 0;

    for (;;) {
        unsigned char op;
        if (pc < 0 || pc >= CODE_LEN) return 0xFFFFFFFFu;
        if (--budget < 0)             return 0xFFFFFFFFu;
        if (O8_FALSE1) { out = m8_add(out, (unsigned int)pc * 0xDEADBEEFu); }  /* opaque junk */
        op = v8_fetch(&ks, &pc);
        switch (op) {
        case 0x10: { int r = v8_fetch(&ks,&pc) & 7; R[r] = state; } break;      /* LDS  */
        case 0x11: { int r = v8_fetch(&ks,&pc) & 7; R[r] = c; } break;          /* LDC  */
        case 0x12: { int r = v8_fetch(&ks,&pc) & 7; R[r] = rc; } break;         /* LDR  */
        case 0x13: { int r = v8_fetch(&ks,&pc) & 7; R[r] = v8_fetch32(&ks,&pc); } break; /* IMM */
        case 0x14: { int d = v8_fetch(&ks,&pc)&7, s = v8_fetch(&ks,&pc)&7; R[d]  = R[s]; } break; /* MOV */
        case 0x15: { int d = v8_fetch(&ks,&pc)&7, s = v8_fetch(&ks,&pc)&7; R[d] = m8_add(R[d], R[s]); } break; /* ADD */
        case 0x16: { int d = v8_fetch(&ks,&pc)&7, s = v8_fetch(&ks,&pc)&7; R[d] = m8_sub(R[d], R[s]); } break; /* SUB */
        case 0x17: { int d = v8_fetch(&ks,&pc)&7, s = v8_fetch(&ks,&pc)&7; R[d] = m8_xor(R[d], R[s]); } break; /* XOR */
        case 0x18: { int d = v8_fetch(&ks,&pc)&7, s = v8_fetch(&ks,&pc)&7; R[d] *= R[s]; } break; /* MUL */
        case 0x19: { int r = v8_fetch(&ks,&pc)&7; R[r] *= v8_fetch32(&ks,&pc); } break;           /* MULI */
        case 0x1A: { int r = v8_fetch(&ks,&pc)&7; R[r] = m8_add(R[r], v8_fetch32(&ks,&pc)); } break; /* ADDI */
        case 0x1B: { int r = v8_fetch(&ks,&pc)&7; R[r] = m8_xor(R[r], v8_fetch32(&ks,&pc)); } break; /* XORI */
        case 0x1C: { int r = v8_fetch(&ks,&pc)&7, a = v8_fetch(&ks,&pc)&31; R[r] = v8_rotl(R[r], a); } break; /* ROL */
        case 0x1D: { int r = v8_fetch(&ks,&pc)&7, a = v8_fetch(&ks,&pc)&31; R[r] = v8_rotl(R[r], (32 - a) & 31); } break; /* ROR */
        case 0x1E: { int r = v8_fetch(&ks,&pc)&7, a = v8_fetch(&ks,&pc)&31; R[r] ^= R[r] >> a; } break; /* SHRX */
        case 0x1F: { int r = v8_fetch(&ks,&pc)&7; out = R[r]; } break;          /* OUT  */
        case 0x20: return out;                                                  /* HALT */
        default:   return 0xFFFFFFFFu;
        }
    }
}

static int run_check_vm(const unsigned char *inner, int n,
                        unsigned int iv, const unsigned short *chk)
{
    unsigned int state = iv;
    unsigned int rc = iv ^ 0xA5A5A5A5u;
    int i;
    for (i = 0; i < n; i++) {
        state = vm_mix(state, inner[i], rc);
        if ((unsigned short)(state & 0xFFFFu) != chk[i])
            return i;
        rc = v8_rotl(rc * 0x9C5AB3D7u + 0x3F1E5C2Bu, 13);
    }
    return n;
}

#endif /* VM8_H */
