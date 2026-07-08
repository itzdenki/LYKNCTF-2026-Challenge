# Writeup - Serial (Cr4ck 3)

**LYKNCTF 2026 — "Serial Check" (chall8)**
**Category:** Reverse Engineering · **Difficulty:** Very Hard (dynamic-only, anti-LLM)
**Flag:** `LYKNCTF{Dyn4m1c_0nly_LYKN_2026!!}`

## Challenge Info

The release package contains a single Windows x64 GUI binary:

- `dist/Serial.exe` — the challenge (player copy in `public/`)

A serial validator that accepts exactly one key — and that key is the
flag. The player enters a serial of the form `LYKNCTF{` + 24 chars + `}`
and presses "Check it!". Reading the binary won't help; you'll have to
make it talk.

## Honest Framing (Read This)

A solvable challenge can never be "100% unsolvable". Cr4ck 3 targets the
*actual* adversary — a binary **pasted into ChatGPT** — whose structural
blind spot is that it **cannot execute a Windows GUI PE** and cannot, in a
short pasted session, faithfully re-implement a self-modifying checker. So
Cr4ck 3 makes the **only practical solve path dynamic**: you must *run*
the binary and read its progress oracle. A fully-tooled LLM agent with a
Windows sandbox is *slowed*, not proven impossible — that is stated, not
hidden.

## Mechanism

Flag = `LYKNCTF{` + 24 bytes + `}`. The checker is a **rolling one-way hash
with per-byte 16-bit checkpoints and early exit**:

```
state = IV
for i in 0..23:
    state = MIX(state, in[i])          # custom ARX, avalanching, lossy
    if (state & 0xFFFF) != CHK[i]:     # 16-bit checkpoint (embedded)
        stop;  progress = i
progress = 24 -> accept
```

- Only 16 bits of state leak per step and the flag is never stored, so
  there is **nothing to invert** from `CHK[]`.
- The **early exit** exposes how many leading bytes matched
  (`g_state.progress`). That is the **dynamic oracle**: fix the known-good
  prefix, vary byte `i` over ~95 printables, and whichever value advances
  `progress` is correct → solve left-to-right. **This needs the program to
  run.**

## Why Static Reconstruction Is Impractical for a Paste Session

- **MIX runs in a VM whose bytecode is chain-encrypted.** `g_code_enc` is
  under a self-synchronizing stream cipher keyed on *plaintext history*:
  to decrypt byte `j` you must have decrypted `0..j-1`. There is **no
  moment where the whole program is in the clear** — recovering MIX means
  faithfully emulating the entire rolling decrypt, which a paste-LLM
  cannot reliably do (and even then it must then reconstruct the IV).
- **IV is derived at runtime**, not stored: `IV = u32(SHA256(.text)) XOR
  seed`, where `seed` is set **before main by a TLS callback** (present in
  the PE's TLS directory) — off the obvious code path. Because it folds
  in `SHA256(.text)`, a patched binary computes a different IV and rejects
  the true flag (anti-tamper).
- **No crypto tells.** MIX and the stream cipher use custom constants (no
  golden-ratio / Murmur / AES / RC4 signature). SHA-256 appears only in the
  one-shot IV derivation, not in the hot loop.
- **Light obfuscation.** The VM's arithmetic is MBA behind optimizer
  barriers with opaque predicates, so a decompiler won't cleanly show
  "add/xor".
- **No result-poisoning anti-debug** — deliberately. We *want* you to run
  it in a debugger; that is the intended tool. (A tool must, however, pass
  the app's own behavior through — e.g. our solver drives it via the live
  process.)

## Intended Solve (Dynamic)

Run it, and brute-force byte-by-byte using the progress oracle:

1. Find the checker's progress counter (`g_state.progress`, right after
   the 8-byte `PRG8LYKN` marker) by watching memory / the compare in a
   debugger.
2. For each position, try printables until `progress` advances; that's the
   byte.
3. 24 × ~95 ≈ a couple thousand attempts.

`solve_dynamic.c` does this against the **shipped** binary with no baked
secrets — it launches `Serial.exe`, locates the marker, and reads
`progress` after each attempt. It recovers the flag in ~30–40 s:

```bash
gcc -O2 -o solve_dynamic.exe solve_dynamic.c -luser32
solve_dynamic.exe dist/Serial.exe
# [+] byte 23 = '!'  -> ...
# [+] FLAG: LYKNCTF{Dyn4m1c_0nly_LYKN_2026!!}
```

## Verified

| Property | Check |
|---|---|
| C VM == reference MIX | `tools/harness.c` (vm_mix vs MIX, 5000 triples) |
| Check is solvable byte-by-byte | in-process oracle solve in `harness.c` |
| Two-pass `.text` stable | build prints one hash both passes |
| GUI golden path | correct serial → accepted; wrong → rejected |
| **Dynamic end-to-end solve** | `solve_dynamic.c` recovers the flag from the shipped binary (~36 s) |
| No leak / no tells | `strings` clean; no golden-ratio; TLS dir present |
| Bytecode not static | `g_code_enc` is chain-encrypted (no cleartext program at rest) |

## Build

Toolchain: **MSYS2 UCRT64** (`gcc`, `windres`, `objcopy`) + **Python**.

```bash
cd src
powershell -File build.ps1     # runs tools/gen.py twice, prints stable .text hash, outputs to ../dist/Serial.exe
```

Change the flag: edit the 24 inner chars in `src/secret_config.h` (exactly
24) and rebuild. MIX/ISA/stream-cipher live in `tools/gen.py` (source of
truth) and `src/vm8.h` / `src/mix.h` — keep them in sync via the harness.

## File Map

```
Cr4ck 3/
├─ README.md               this file (author writeup, contains the flag)
├─ solve_dynamic.c         debugger/oracle dynamic solver (from shipped binary)
├─ dist/
│  └─ Serial.exe           built release binary
├─ public/                 player-facing package
│  ├─ Serial.exe
│  ├─ README.txt           player brief
│  └─ lyknctf.png          banner art
├─ src/                    full source, do not ship
│  ├─ crackme8.c           GUI + rolling check + progress oracle (marker)
│  ├─ mix.h                reference MIX + run_check
│  ├─ vm8.h                chain-encrypted VM (MIX) + obfuscation
│  ├─ tls.h                TLS callback seeding the IV (pre-main)
│  ├─ selfhash.h / sha256.h   .text self-hash for the IV
│  ├─ check_data.h         generated: CHK[] + encrypted bytecode
│  ├─ secret_config.h      the flag (build-only secret!)
│  ├─ crackme8.rc / crackme.manifest / banner.bmp
│  └─ build.ps1            two-pass build (ASLR off) + .text verify
└─ tools/                  do not ship
   ├─ gen.py               MIX + CHK gen + bytecode assemble/encrypt
   └─ harness.c            VM parity + in-process oracle solve
```

## Flag

```text
LYKNCTF{Dyn4m1c_0nly_LYKN_2026!!}
```
