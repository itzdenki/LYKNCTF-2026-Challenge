# Writeup - Activator (Cr4ck 2)

**LYKNCTF 2026 — "License Activation" (chall7)**
**Category:** Reverse Engineering · **Difficulty:** Very Hard (anti-LLM)
**Flag:** `LYKNCTF{V1rtu4l_ARX_VM_LLM_h3ll_LYKN2026}`

## Challenge Info

The release package contains a single Windows x64 GUI binary:

- `dist/Activator.exe` — the challenge (player copy in `public/`)

The "License Activator" accepts exactly one valid key — and that key is
the flag. The player enters an Activation Key of the form
`LYKNCTF{` + 32 chars + `}` and presses "Check it!". The validation logic
is not written in a language a decompiler will enjoy.

## Design Goal

Cr4ck 1 was solved by ChatGPT in ~3 minutes because everything in it is
*recognizable* (standard SHA-256/RC4, a short readable ARX). Cr4ck 2 is
built to deny an LLM (and its tools) every one of those shortcuts. There is
**no recognizable primitive**, the check logic **isn't native code**, and
the flag is a **preimage** you must invert — not a value you can read or
patch to.

## What It Is

The activation key **is** the flag: `LYKNCTF{` + 32 bytes + `}`. Those 32
bytes are the plaintext of a bespoke **ARX permutation**; the binary
stores only `target = ARX_permute(flag_inner)`. Acceptance is
`ARX_permute(input) == target`.

Crucially, the permutation and the comparison run inside a **custom
register bytecode VM**, and the bytecode is stored **XOR-encrypted**:

```
decode_key = SHA256( SHA256(.text) || dbg_byte || salt )
bytecode   = g_prog_enc XOR CTR-keystream(decode_key)
```

## Why It Resists an LLM and Its Tools

- **Virtualization.** `vm_execute` in the binary is a ~17-opcode
  interpreter (plus decoy opcodes). To learn what the program *does*, you
  must reconstruct the ISA from the interpreter, then trace 183 bytes of
  bytecode. LLMs are error-prone over long manual emulations.
- **Encrypted bytecode + folded anti-analysis.** The program is unreadable
  until you realise it is XOR-encrypted and derive the exact key. That key
  folds in `SHA256(.text)` (**anti-tamper** — any patched byte → wrong key
  → garbage program → reject) and an anti-debug byte from
  PEB/`NtQueryInformationProcess` (**anti-debug** — a debugger poisons the
  key). ASLR is disabled so the runtime self-hash is deterministic; the
  build is two-pass (measure `.text` → encrypt → rebuild).
- **Custom crypto, no signature.** The permutation is a hand-rolled ARX
  (add / rotate / xor, Weyl round constants) with no SHA/AES/RC4 pattern
  for a matcher.
- **Preimage, not a branch.** Even a perfect patch of every compare cannot
  print the flag: the flag is `ARX_permute^-1(target)`, recovered by
  *understanding* the algorithm.
- **Anti-solver.** Lifting the VM still leaves `ARX_permute(x)==target`
  over 256-bit state, 32 ARX rounds — a preimage problem angr/Z3 cannot
  crack. Whole-binary emulation is impractical (Win32 GUI + PEB
  self-hash/anti-debug deps).
- **Obfuscation.** The interpreter's arithmetic is rewritten as MBA (mixed
  boolean-arithmetic) behind optimizer barriers, guarded by opaque
  predicates, with decoy opcodes — so Hex-Rays output never says "just
  add/xor".

## Intended Solve

1. Recognise the interpreter as a VM; recover its opcode semantics.
2. Notice the bytecode is XOR-encrypted; compute `SHA256(.text)` yourself,
   `dbg=0`, `salt=0x4C594B37` (from `vm_decode`), derive the key, decrypt
   the 183-byte program.
3. Disassemble it: it's an ARX permutation — `SEED=0x1BADC0DE`,
   `DELTA=0x9E3779B9` (Weyl), `ROUNDS=32`, rotations
   `[7,9,13,18,3,11,17,5]`, per lane
   `s[i]+=k; s[i]=rol(s[i],rot[i]); s[i]^=s[(i+1)&7]`.
4. It's a **bijection** → run it backwards on the 32-byte `target` to get
   the 32 plaintext bytes = the flag.

`solve.py <Activator.exe>` does all four **from the binary alone** (hashes
`.text`, decrypts the bytecode by scanning for it, extracts the constants,
inverts the target):

```bash
python solve.py dist/Activator.exe
# [+] SEED=0x1BADC0DE DELTA=0x9E3779B9 ROUNDS=32 ROT=[7, 9, 13, 18, 3, 11, 17, 5]
# [+] FLAG: LYKNCTF{V1rtu4l_ARX_VM_LLM_h3ll_LYKN2026}
```

## Verified

| Property | Check |
|---|---|
| C VM == Python reference | `tools/harness.c` vs `tools/parity.py` (identical, incl. after obfuscation) |
| Two-pass `.text` stable | build prints one hash for both passes |
| Golden path | correct key → "Activation successful"; wrong → reject |
| No flag / no primitive leak | `strings` clean; bytecode blob entropy ≈ 6.85 bits/byte |
| Anti-tamper | flip one `.text` padding byte → correct key rejected |
| Anti-debug | run under `DEBUG_ONLY_THIS_PROCESS` → correct key rejected |
| Solvable | `solve.py` recovers the flag from the binary alone |

## Build

Toolchain: **MSYS2 UCRT64** (`gcc`, `windres`, `objcopy`) + **Python**.

```bash
cd src
powershell -File build.ps1     # runs tools/asm.py twice, prints stable .text hash, outputs to ../dist/Activator.exe
```

To change the flag: edit the 32 inner chars in `src/secret_config.h` (must
be exactly 32) and rebuild. The ISA/ARX live in `tools/asm.py` (single
source of truth) and `src/vm.h` (interpreter) — keep them in sync via the
harness.

## File Map

```
Cr4ck 2/
├─ README.md               this file (author writeup, contains the flag)
├─ solve.py                full offline flag recovery
├─ dist/
│  └─ Activator.exe        built release binary
├─ public/                 player-facing package
│  ├─ Activator.exe
│  ├─ README.txt           player brief
│  └─ lyknctf.png          banner art
├─ src/                    full source, do not ship
│  ├─ crackme7.c           GUI + do_check (decode bytecode, run VM)
│  ├─ vm.h                 obfuscated register VM interpreter
│  ├─ vmload.h             bytecode decode (key = SHA256(.text||dbg||salt))
│  ├─ vm_program.h         generated: g_prog_enc, g_target_b, PROG_LEN, salt
│  ├─ sha256.h / antidbg.h / selfhash.h   (shared utilities)
│  ├─ secret_config.h      the flag (build-only secret!)
│  ├─ crackme7.rc / crackme.manifest / banner.bmp
│  └─ build.ps1            two-pass build + ASLR off + .text verify
└─ tools/                  do not ship
   ├─ asm.py               assembler + emulator + ARX ref + target/encrypt
   ├─ harness.c            C-vs-Python parity harness
   └─ parity.py            parity reference
```

## Flag

```text
LYKNCTF{V1rtu4l_ARX_VM_LLM_h3ll_LYKN2026}
```
