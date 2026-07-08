#ifndef FLAGCRYPT_H
#define FLAGCRYPT_H
/*
 * Flag key-derivation + keystream, shared by crackme.c and gen_flag.c so
 * runtime decryption and build-time encryption can never drift.
 *
 *   K          = SHA256( user || 0x1F || key || 0x1F || text_hash || dbg )
 *   keystream  = SHA256(K || ctr) blocks (CTR mode)
 *   ciphertext = plaintext XOR keystream
 *   tag        = SHA256("LYKN2026" || flag)[:8]     (integrity / success gate)
 *
 * Build encrypts with (U, serial, text_hash0, 0); runtime derives with the
 * bytes the user typed + the live self-hash + anti-debug byte. The flag
 * only appears when all of those match the build-time values.
 */
#include "sha256.h"

#define FLAG_CTLEN 96      /* fixed ciphertext length -> hides flag length */

static void lykn_derive_key(const unsigned char *user, int ulen,
                            const unsigned char *key,  int klen,
                            const unsigned char text_hash[32],
                            unsigned char dbg, unsigned char K[32])
{
    sha256_ctx c;
    unsigned char sep = 0x1F;
    sha256_init(&c);
    sha256_update(&c, user, (unsigned int)ulen);
    sha256_update(&c, &sep, 1);
    sha256_update(&c, key, (unsigned int)klen);
    sha256_update(&c, &sep, 1);
    sha256_update(&c, text_hash, 32);
    sha256_update(&c, &dbg, 1);
    sha256_final(&c, K);
}

static void lykn_keystream(const unsigned char K[32], unsigned char out[FLAG_CTLEN])
{
    int off, j;
    for (off = 0; off < FLAG_CTLEN; off += 32) {
        unsigned int idx = (unsigned int)(off / 32);
        unsigned char ib[4], ks[32];
        sha256_ctx k;
        ib[0] = (unsigned char)idx;
        ib[1] = (unsigned char)(idx >> 8);
        ib[2] = (unsigned char)(idx >> 16);
        ib[3] = (unsigned char)(idx >> 24);
        sha256_init(&k);
        sha256_update(&k, K, 32);
        sha256_update(&k, ib, 4);
        sha256_final(&k, ks);
        for (j = 0; j < 32; j++) out[off + j] = ks[j];
    }
}

static void lykn_tag(const unsigned char *flag, int flen, unsigned char tag8[8])
{
    sha256_ctx t;
    unsigned char full[32];
    int i;
    sha256_init(&t);
    sha256_update(&t, (const unsigned char *)"LYKN2026", 8);
    sha256_update(&t, flag, (unsigned int)flen);
    sha256_final(&t, full);
    for (i = 0; i < 8; i++) tag8[i] = full[i];
}

#endif /* FLAGCRYPT_H */
