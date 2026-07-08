#ifndef SECRET_CONFIG_H
#define SECRET_CONFIG_H
/*
 * BUILD-TIME SECRETS -- consumed ONLY by gen_flag.c, never compiled into
 * the shipped crackme. DO NOT SHIP THIS FILE.
 *
 * TARGET_USER : the hidden account that unlocks the flag. It is stored in
 *               the binary XOR-obfuscated (see lykn_obf_user), so it does
 *               not appear in `strings`; players must recover it.
 * FLAG_TEXT   : the flag, encrypted with a key derived from
 *               TARGET_USER + its serial + the binary's .text hash.
 */
#define TARGET_USER "th3_LYKN_v3nd0r"
#define FLAG_TEXT   "LYKNCTF{k3yg3n_h3ll_s3lfh4sh_4ntidbg_h1dd3n_us3r_2026}"

#endif /* SECRET_CONFIG_H */
