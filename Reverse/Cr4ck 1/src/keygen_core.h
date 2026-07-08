#ifndef KEYGEN_CORE_H
#define KEYGEN_CORE_H
/*
 * Shared keygen core -- included by the crackme (crackme.c), the flag
 * generator (gen_flag.c) and the official keygen (keygen.c), so they can
 * never drift apart.
 *
 *   key(username) = "XXXX-XXXX-XXXX-XXXX-XXXX"   (upper-case hex)
 *
 * Non-linear on purpose: an RC4-style key-scheduled S-box, three passes
 * over the username with ARX mixing, then a finalisation avalanche.
 * It stays fully FORWARD-deterministic, so a solver just re-implements it.
 *
 * The `dbg` byte is XORed into the seed. On a clean run dbg==0 and the
 * serial is canonical; under a debugger the anti-debug layer makes dbg!=0,
 * so every serial the program computes is wrong -- defeating "set a
 * breakpoint and read the expected key".
 */

#ifndef KG_NOINLINE
#define KG_NOINLINE
#endif

static KG_NOINLINE unsigned int kg_rotl32(unsigned int x, int r)
{
    return (x << r) | (x >> (32 - r));
}

/* RC4-style key schedule -> 256-byte substitution box. */
static KG_NOINLINE void kg_ksa(unsigned char S[256])
{
    static const unsigned char key[15] = {
        'L','0','i','_','Y','3','u','_','K','h','0','_','N','0','i'
    };
    int i, j = 0;
    unsigned char t;
    for (i = 0; i < 256; i++) S[i] = (unsigned char)i;
    for (i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % 15]) & 0xFF;
        t = S[i]; S[i] = S[j]; S[j] = t;
    }
}

/* Mix the username into four 32-bit lanes. */
static KG_NOINLINE void kg_state(const unsigned char *u, int n,
                                 unsigned char dbg, unsigned int h[4])
{
    unsigned char S[256];
    unsigned int h0, h1, h2, h3;
    int r, i;

    kg_ksa(S);

    h0 = 0x4C594B4Eu ^ ((unsigned int)dbg * 0x01010101u);  /* 'LYKN' */
    h1 = 0x43544632u;                                       /* 'CTF2' */
    h2 = 0x30323600u ^ 0x9E3779B9u;                         /* '026'  */
    h3 = 0xA5A5F00Du;

    for (r = 0; r < 3; r++) {
        for (i = 0; i < n; i++) {
            unsigned int c = S[(u[i] + r * 7) & 0xFF];
            h0 = kg_rotl32(h0 ^ c, 5)  + h1;
            h1 = kg_rotl32(h1 + c, 11) ^ h2;
            h2 = kg_rotl32(h2 ^ (c * 0x9E3779B1u), 17) + h3;
            h3 = kg_rotl32(h3 + S[h0 & 0xFF], 3) ^ h0;
        }
    }

    for (r = 0; r < 4; r++) {                                /* avalanche */
        h0 += h3; h1 ^= kg_rotl32(h0, 7);
        h2 += h1; h3 ^= kg_rotl32(h2, 13);
    }

    h[0] = h0; h[1] = h1; h[2] = h2; h[3] = h3;
}

/* Format "XXXX-XXXX-XXXX-XXXX-XXXX" (needs 25 bytes). Block 5 is a
 * checksum over the first four, so a random-looking key is self-invalid. */
static KG_NOINLINE void lykn_keygen(const char *user, int len,
                                    unsigned char dbg, char *out)
{
    static const char HEX[] = "0123456789ABCDEF";
    unsigned int h[4], blk[5];
    int b, i, p = 0;

    kg_state((const unsigned char *)user, len, dbg, h);

    blk[0] =  (h[0] >> 16) & 0xFFFFu;
    blk[1] =  (h[0] ^ h[1]) & 0xFFFFu;
    blk[2] =  (h[1] >> 16) & 0xFFFFu;
    blk[3] =  (h[2] ^ h[3]) & 0xFFFFu;
    blk[4] = ((blk[0] + blk[1] + blk[2] + blk[3]) ^ (h[2] >> 16)) & 0xFFFFu;

    for (b = 0; b < 5; b++) {
        if (b) out[p++] = '-';
        for (i = 12; i >= 0; i -= 4)
            out[p++] = HEX[(blk[b] >> i) & 0xF];
    }
    out[p] = '\0';
}

/* Obfuscate/deobfuscate the hidden target username with the KSA S-box
 * (symmetric XOR). Keeps the target user out of `strings`; recovering it
 * means reproducing the S-box. Same call both directions. */
static KG_NOINLINE void lykn_obf_user(const unsigned char *in, int len,
                                      unsigned char *out)
{
    unsigned char S[256];
    int i;
    kg_ksa(S);
    for (i = 0; i < len; i++)
        out[i] = in[i] ^ S[(i * 5 + 0x1F) & 0xFF];
}

#endif /* KEYGEN_CORE_H */
