#ifndef SHA256_H
#define SHA256_H
/*
 * Compact, self-contained SHA-256 (public-domain style).
 * Shared by the crackme and the build-time flag generator so the
 * key-derivation can never drift. No external deps, no BCrypt import.
 */

typedef struct {
    unsigned int  state[8];
    unsigned long long bitlen;
    unsigned char data[64];
    unsigned int  datalen;
} sha256_ctx;

#define SHA256_ROTR(x,n) (((x) >> (n)) | ((x) << (32 - (n))))
#define SHA256_CH(x,y,z)  (((x) & (y)) ^ (~(x) & (z)))
#define SHA256_MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SHA256_EP0(x) (SHA256_ROTR(x,2) ^ SHA256_ROTR(x,13) ^ SHA256_ROTR(x,22))
#define SHA256_EP1(x) (SHA256_ROTR(x,6) ^ SHA256_ROTR(x,11) ^ SHA256_ROTR(x,25))
#define SHA256_SIG0(x) (SHA256_ROTR(x,7) ^ SHA256_ROTR(x,18) ^ ((x) >> 3))
#define SHA256_SIG1(x) (SHA256_ROTR(x,17) ^ SHA256_ROTR(x,19) ^ ((x) >> 10))

static const unsigned int SHA256_K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static void sha256_transform(sha256_ctx *c, const unsigned char *d)
{
    unsigned int i, j, t1, t2, m[64];
    unsigned int A, B, C, D, E, F, G, H;

    for (i = 0, j = 0; i < 16; i++, j += 4)
        m[i] = ((unsigned int)d[j] << 24) | ((unsigned int)d[j+1] << 16)
             | ((unsigned int)d[j+2] << 8) | ((unsigned int)d[j+3]);
    for (; i < 64; i++)
        m[i] = SHA256_SIG1(m[i-2]) + m[i-7] + SHA256_SIG0(m[i-15]) + m[i-16];

    A=c->state[0]; B=c->state[1]; C=c->state[2]; D=c->state[3];
    E=c->state[4]; F=c->state[5]; G=c->state[6]; H=c->state[7];

    for (i = 0; i < 64; i++) {
        t1 = H + SHA256_EP1(E) + SHA256_CH(E,F,G) + SHA256_K[i] + m[i];
        t2 = SHA256_EP0(A) + SHA256_MAJ(A,B,C);
        H = G; G = F; F = E; E = D + t1;
        D = C; C = B; B = A; A = t1 + t2;
    }

    c->state[0]+=A; c->state[1]+=B; c->state[2]+=C; c->state[3]+=D;
    c->state[4]+=E; c->state[5]+=F; c->state[6]+=G; c->state[7]+=H;
}

static void sha256_init(sha256_ctx *c)
{
    c->datalen = 0; c->bitlen = 0;
    c->state[0]=0x6a09e667; c->state[1]=0xbb67ae85;
    c->state[2]=0x3c6ef372; c->state[3]=0xa54ff53a;
    c->state[4]=0x510e527f; c->state[5]=0x9b05688c;
    c->state[6]=0x1f83d9ab; c->state[7]=0x5be0cd19;
}

static void sha256_update(sha256_ctx *c, const unsigned char *data, unsigned int len)
{
    unsigned int i;
    for (i = 0; i < len; i++) {
        c->data[c->datalen++] = data[i];
        if (c->datalen == 64) {
            sha256_transform(c, c->data);
            c->bitlen += 512;
            c->datalen = 0;
        }
    }
}

static void sha256_final(sha256_ctx *c, unsigned char out[32])
{
    unsigned int i = c->datalen;
    c->data[i++] = 0x80;
    if (c->datalen < 56) {
        while (i < 56) c->data[i++] = 0x00;
    } else {
        while (i < 64) c->data[i++] = 0x00;
        sha256_transform(c, c->data);
        for (i = 0; i < 56; i++) c->data[i] = 0x00;
    }
    c->bitlen += (unsigned long long)c->datalen * 8;
    c->data[63] = (unsigned char)(c->bitlen);
    c->data[62] = (unsigned char)(c->bitlen >> 8);
    c->data[61] = (unsigned char)(c->bitlen >> 16);
    c->data[60] = (unsigned char)(c->bitlen >> 24);
    c->data[59] = (unsigned char)(c->bitlen >> 32);
    c->data[58] = (unsigned char)(c->bitlen >> 40);
    c->data[57] = (unsigned char)(c->bitlen >> 48);
    c->data[56] = (unsigned char)(c->bitlen >> 56);
    sha256_transform(c, c->data);
    for (i = 0; i < 4; i++) {
        out[i]      = (unsigned char)(c->state[0] >> (24 - i*8));
        out[i+4]    = (unsigned char)(c->state[1] >> (24 - i*8));
        out[i+8]    = (unsigned char)(c->state[2] >> (24 - i*8));
        out[i+12]   = (unsigned char)(c->state[3] >> (24 - i*8));
        out[i+16]   = (unsigned char)(c->state[4] >> (24 - i*8));
        out[i+20]   = (unsigned char)(c->state[5] >> (24 - i*8));
        out[i+24]   = (unsigned char)(c->state[6] >> (24 - i*8));
        out[i+28]   = (unsigned char)(c->state[7] >> (24 - i*8));
    }
}

static void sha256(const unsigned char *data, unsigned int len, unsigned char out[32])
{
    sha256_ctx c;
    sha256_init(&c);
    sha256_update(&c, data, len);
    sha256_final(&c, out);
}

#endif /* SHA256_H */
