#ifndef SECRET_CONFIG_H
#define SECRET_CONFIG_H
/*
 * BUILD-TIME SECRET -- consumed only by tools/asm.py to compute the target.
 * DO NOT SHIP THIS FILE.
 *
 * The 32 characters between the braces are the plaintext block; the target
 * embedded in the binary is ARX_permute(those 32 bytes). Recovering the flag
 * means inverting the permutation.
 */
#define FLAG_TEXT "LYKNCTF{V1rtu4l_ARX_VM_LLM_h3ll_LYKN2026}"

#endif /* SECRET_CONFIG_H */
