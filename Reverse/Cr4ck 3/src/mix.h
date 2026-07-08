#ifndef MIX_H
#define MIX_H
/*
 * The rolling one-way checker core (stage 2: plain C; later moved into the VM).
 *
 *   state = IV
 *   for i: state = MIX(state, inner[i], rc[i]);  check (state & 0xFFFF) == CHK[i]
 *
 * MIX avalanches state with the input byte and a rolling round constant.
 * Custom constants (no golden-ratio / Murmur / SHA signature). It is lossy
 * (40 bits in, 32 out) and only 16 bits of state leak per step, so the flag
 * cannot be inverted from CHK[] without the full runtime state chain.
 *
 * run_check returns the number of leading bytes that matched (== n on full
 * pass) -- this count is the dynamic progress oracle.
 */

static unsigned int mix_rotl(unsigned int x, int r)
{ return (x << r) | (x >> (32 - r)); }

static unsigned int MIX(unsigned int s, unsigned int c, unsigned int rc)
{
    s ^= c * 0x53u + rc;
    s  = mix_rotl(s, 7);
    s ^= s >> 13;
    s  = (s + rc) * 0x9C5AB3D7u;
    s  = mix_rotl(s, 11);
    s ^= s >> 17;
    s += 0x3F1E5C2Bu;
    return s;
}

static int run_check(const unsigned char *inner, int n,
                     unsigned int iv, const unsigned short *chk)
{
    unsigned int state = iv;
    unsigned int rc = iv ^ 0xA5A5A5A5u;
    int i;
    for (i = 0; i < n; i++) {
        state = MIX(state, inner[i], rc);
        if ((unsigned short)(state & 0xFFFFu) != chk[i])
            return i;                       /* matched i bytes, failed at i */
        rc = mix_rotl(rc * 0x9C5AB3D7u + 0x3F1E5C2Bu, 13);
    }
    return n;                               /* full pass */
}

#endif /* MIX_H */
