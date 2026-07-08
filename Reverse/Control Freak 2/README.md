# Control Freak 2

## Challenge Info

The release contains 2 binaries:

- `chall-3`: Linux x86_64 ELF (stripped)
- `chall-3.exe`: Windows x86_64 PE (stripped)

The program is a flag checker. The binary takes the flag via argv or stdin:

```bash
./chall-3
flag:
```

If correct it prints `Correct!`, if wrong it prints `Nope`.

## Recon

`strings` shows no plaintext flag, only `flag:`, `Correct!`, `Nope`. The binary
has stripped symbols. The `main` flow:

1. Read input from argv or stdin.
2. Call one large check function (`guarded_check`).
3. True -> `Correct!`, false -> `Nope`.

## Checker Structure

`guarded_check` is a state-machine dispatcher (states are constants like
`0x91cf3a2b`, `0xd2387a55`, `0x0f6d3c2a`...) wrapping 4 real steps:

```c
poison = anti_probe();                    // anti-analysis
len    = bounded_len(input);
transform(input, len, poison, cipher);    // encrypt the input
memcpy(expected, kCipher, 30);            // constant embedded in the binary
return cipher == expected && poison == 0; // comparison
```

Noise layers (don't change the result on a clean run):

- **Anti-analysis** (`anti_probe`): timing probe, Windows `IsDebuggerPresent` /
  `CheckRemoteDebuggerPresent` / PEB `BeingDebugged` / `NtGlobalFlag` / debug
  registers; Linux `/proc/self/status` TracerPid + `ptrace(PTRACE_TRACEME)` +
  env hook. If being debugged, `poison != 0` -> the keystream shifts and
  `diff |= poison` -> always `Nope`, with no warning printed. On a clean run
  `poison == 0`.
- **Opaque predicate** (`opaque_true` / `opaque_false`) + **fake_path**: a fake
  branch that only runs when `opaque_false` == true (never happens), added to
  confuse the decompiler.
- **VMProtect markers**: `VMProtectBeginUltra/Mutation` (only active when built
  with `-DUSE_VMPROTECT` + external packing).

## Difference From The Previous Challenge: The Transform Is INVERTIBLE

Unlike the previous version (one-way hash, unrecoverable), this time the core
is a chain of **invertible** per-byte transformations, so the flag can be
recovered 100% from `kCipher`.

For each byte `i` (`prev` initialized to `kChainIV = 0xA5`):

```
t = flag[i] ^ keystream[i]          // keystream = splitmix64(kKeyStreamSeed)
t = (t + (i*37 + 0x5A)) & 0xFF      // position constant
t = rotl8(t, i & 7)                 // in-byte rotation
t = SBOX[t]                         // S-box, Fisher-Yates seeded with kSboxSeed
t = t ^ prev                        // CBC-style chaining
cipher[i] = t ; prev = t
```

All constants live in the binary:

- `kCipher[30]` — the constant being compared against (ciphertext of the flag).
- `kKeyStreamSeed = 0xD1B54A32D192ED03` — splitmix64 keystream seed.
- `kSboxSeed = 0x9E3779B97F4A7C15` — Fisher-Yates seed used to generate the S-box.
- `kChainIV = 0xA5` — chaining IV.

## Intended Path

Since every step has an inverse (xor, add, rotate, S-box, chain xor), invert
`kCipher` directly back into the flag. With `poison = 0` (clean run):

```
prev = kChainIV
for i in 0..29:
    e = cipher[i] ^ prev
    d = INV_SBOX[e]
    b = rotr8(d, i & 7)
    a = (b - (i*37 + 0x5A)) & 0xFF
    flag[i] = a ^ keystream[i]
    prev = cipher[i]
```

`solve.py` does exactly this — it recovers the flag **without the flag string
appearing anywhere**, just by reading constants from the binary and running
the pipeline in reverse.

## Solver

```bash
python solve.py                 # recover the flag from kCipher
# LYKNCTF{1S_1T_H4RD_T0_C0NTR0L}

python solve.py --check 'LYKNCTF{1S_1T_H4RD_T0_C0NTR0L}'
# Correct!

python solve.py --verify-bin    # run the dist binary with the recovered flag
# LYKNCTF{1S_1T_H4RD_T0_C0NTR0L}
# dist/chall-3.exe: exit=0 output=Correct!
# dist/chall-3: exit=0 output=Correct!
```

On Windows, the ELF `dist/chall-3` reports `skipped` because the host can't
run an ELF directly; verify it via WSL/Linux.

## Build

```bash
# Windows PE (MSYS2 g++)
g++ -O2 -s -static -static-libgcc -static-libstdc++ -o dist/chall-3.exe gen.cpp

# Linux ELF (g++)
g++ -O2 -s -o dist/chall-3 gen.cpp
```

## Flag

```text
LYKNCTF{1S_1T_H4RD_T0_C0NTR0L}
```
