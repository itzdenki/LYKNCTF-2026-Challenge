#ifndef SECRET_CONFIG_H
#define SECRET_CONFIG_H
/*
 * BUILD-TIME SECRET -- consumed only by tools/gen.py to compute the per-byte
 * checkpoints. DO NOT SHIP THIS FILE.
 *
 * Flag = LYKNCTF{ + 24 inner bytes + }. The binary stores only 16-bit rolling
 * checkpoints CHK[i]; the flag is never present and cannot be inverted from
 * them. It is recovered by DYNAMICALLY brute-forcing one byte at a time using
 * the checker's own progress (early-exit) oracle.
 */
#define FLAG_TEXT "LYKNCTF{Dyn4m1c_0nly_LYKN_2026!!}"
#define FLAG_INNER_LEN 24

#endif /* SECRET_CONFIG_H */
