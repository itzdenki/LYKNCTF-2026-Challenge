#ifndef VMLOAD_H
#define VMLOAD_H
/*
 * Decrypt the VM bytecode. The decode key folds in the .text self-hash and
 * the anti-debug byte, so a patched or debugged binary decrypts the program
 * to garbage (the VM then rejects everything). Mirrors tools/asm.py:
 *
 *   K  = SHA256( text_hash || dbg || salt_le )
 *   ks = SHA256(K || ctr) blocks (CTR)
 *   prog = enc XOR ks
 */
#include "sha256.h"

static void vm_decode(const unsigned char *enc, int len,
                      const unsigned char text_hash[32], unsigned char dbg,
                      unsigned int salt, unsigned char *out)
{
    sha256_ctx c;
    unsigned char K[32], sb[4];
    int off, j;

    sb[0] = (unsigned char)salt;       sb[1] = (unsigned char)(salt >> 8);
    sb[2] = (unsigned char)(salt >> 16); sb[3] = (unsigned char)(salt >> 24);

    sha256_init(&c);
    sha256_update(&c, text_hash, 32);
    sha256_update(&c, &dbg, 1);
    sha256_update(&c, sb, 4);
    sha256_final(&c, K);

    for (off = 0; off < len; off += 32) {
        sha256_ctx k;
        unsigned int idx = (unsigned int)(off / 32);
        unsigned char ib[4], ks[32];
        ib[0] = (unsigned char)idx;       ib[1] = (unsigned char)(idx >> 8);
        ib[2] = (unsigned char)(idx >> 16); ib[3] = (unsigned char)(idx >> 24);
        sha256_init(&k);
        sha256_update(&k, K, 32);
        sha256_update(&k, ib, 4);
        sha256_final(&k, ks);
        for (j = 0; j < 32 && off + j < len; j++)
            out[off + j] = enc[off + j] ^ ks[j];
    }
}

#endif /* VMLOAD_H */
