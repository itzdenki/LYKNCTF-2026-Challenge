# Writeup - KeygenMe (Cr4ck 1)

**LYKNCTF 2026 — "Loi Yeu Kho Noi" KeygenMe (v2)**
**Category:** Reverse Engineering
**Flag:** `LYKNCTF{k3yg3n_h3ll_s3lfh4sh_4ntidbg_h1dd3n_us3r_2026}`

## Challenge Info

The release package contains a single Windows x64 GUI binary:

- `dist/KeygenMe.exe` — the crackme (player copy in `public/`)

A shady vendor ships premium software locked to a single client account.
The account name is not printed anywhere, and the license check is...
paranoid. The player enters a **Username** and a **License Key**, presses
"Check it!", and must recover the vendor's hidden account, forge its
license key, and run the program cleanly to get the flag.

## Recon

`strings` is a dead end: the flag, the hidden account name, and the correct
license key are never stored in clear text. The GUI logic in `crackme.c`
routes through a KDF-based unlock instead of a simple string compare.

## Why the v1 Approach Is Dead

v1 stored the flag XOR'd against a fixed **LCG** keystream in a
self-contained `reveal_flag()`. That let players ignore the keygen
entirely: dump the 44-byte blob, replay the `rand()` constants, done.
Patching `jne -> jmp` also worked.

v2 removes every one of those shortcuts. **There is no branch that
"reveals" the flag** — the flag is the *plaintext* of a scheme whose key is
derived from everything that must simultaneously be correct.

## The Unlock

```
K          = SHA256( username || 0x1F || serial || 0x1F || SHA256(.text) || dbg )
keystream  = SHA256(K || ctr_0) || SHA256(K || ctr_1) || SHA256(K || ctr_2)   (96 bytes)
plaintext  = g_ct XOR keystream
show flag ⇔ SHA256("LYKN2026" || plaintext)[:8] == g_tag
```

Consequences:

- **Reading `g_ct`** (visible in `.rdata`) is useless without `K`.
- **Patching the compares** is useless: the flag never depends on them, and
  any code edit changes `SHA256(.text)` -> wrong `K` -> tag fails.
- **Calling the decrypt** directly is useless: it needs the exact inputs.
- **Debugging** sets `dbg != 0`, which poisons both the serial and `K`.

So the flag only appears on a **clean, un-patched** binary fed the **hidden
target user** and **its correct serial**.

## Three Things to Reverse

### (a) Recover the hidden user (`lykn_obf_user`, `src/keygen_core.h`)

The target account is not in `strings`; it is `g_encu` XOR the RC4-KSA
S-box:

```python
from keygen import ksa
encu = [...]                      # g_encu bytes, read from the binary
S = ksa()
U = bytes(encu[i] ^ S[(i*5+0x1F)&0xFF] for i in range(len(encu)))
# -> b"th3_LYKN_v3nd0r"
```

### (b) Reverse the keygen (`lykn_keygen` / `kg_state` / `kg_ksa`, `src/keygen_core.h`)

`key(user) = "XXXX-XXXX-XXXX-XXXX-XXXX"`. An RC4-scheduled 256-byte S-box,
three passes over the username through four ARX lanes, a finalisation
avalanche, then five 16-bit blocks (block 5 is a checksum). It is fully
forward-deterministic — a keygen just re-runs it (see `keygen.py` /
`keygen.c`).

For the hidden user: `serial = 7211-57C4-CD96-CC26-5B67`.

> The `dbg` byte is XOR'd into the seed. Under a debugger `dbg != 0`, so
> **every serial the program prints/compares is wrong** — you cannot
> breakpoint and read the expected serial. This forces static reversing of
> the keygen.

### (c) Feed it clean

Type `th3_LYKN_v3nd0r` + `7211-57C4-CD96-CC26-5B67` into the real binary,
no debugger, no patches -> the vault opens and prints the flag.

## Solver

`solve.py <KeygenMe.exe> <user>` reproduces everything without running the
target: it parses the PE, hashes `.text` (VirtualSize bytes at
PointerToRawData — matches the in-memory self-hash because ASLR is
disabled), computes the serial via `keygen.py`, derives `K`, builds the
keystream, and **scans `.rdata`** for the 96-byte window that decrypts to
`LYKNCTF{...}`.

```bash
python solve.py dist/KeygenMe.exe th3_LYKN_v3nd0r
# [+] FLAG: LYKNCTF{k3yg3n_h3ll_s3lfh4sh_4ntidbg_h1dd3n_us3r_2026}
```

`keygen.py` / `keygen.c` (compiled as `keygen.exe`) are the standalone
forward keygen — given a username they print the matching license key,
sharing the exact algorithm in `src/keygen_core.h`.

```bash
python keygen.py th3_LYKN_v3nd0r
# License  : 7211-57C4-CD96-CC26-5B67
```

## Anti-Analysis Layers (Verified)

| Layer | File | Verified by |
|---|---|---|
| Key-derived flag (no reveal branch) | `crackme.c` / `flagcrypt.h` | golden path unlocks; blob alone useless |
| KDF = SHA-256 CTR (no LCG, fixed 96B) | `flagcrypt.h` / `sha256.h` | `strings` shows no LCG/flag/length |
| Non-linear keygen (S-box+rounds+checksum) | `keygen_core.h` | py<->C match; longer serial |
| Hidden target user (obfuscated) | `keygen_core.h` | not in `strings`; recovered via KSA |
| Anti-debug (PEB + NtQueryInformationProcess) | `antidbg.h` | under debugger: correct inputs -> "Wrong license key", no flag |
| Anti-tamper (SHA-256 of .text into K) | `selfhash.h` | flip one padding byte -> "vault stays locked" |

ASLR/high-entropy VA disabled at link (`--disable-dynamicbase`) so the
runtime `.text` equals the on-disk `.text` the generator hashed. The build
is **two-pass** (measure `.text` -> encrypt flag against it -> rebuild);
`.text` is byte-identical across passes because the ciphertext lives in
`.rdata`.

## Build

Toolchain: **MSYS2 UCRT64** (`gcc`, `windres`, `objcopy`).

```bash
cd src
powershell -File build.ps1     # two-pass, prints the stable .text hash, outputs to ../dist/KeygenMe.exe
```

To change the flag or hidden user, edit `src/secret_config.h` and rebuild;
then update `keygen.py` / `keygen.c` only if you change the algorithm.

## File Map

```
Cr4ck 1/
├─ README.md               this file (author writeup, contains the flag)
├─ solve.py                full offline flag recovery
├─ keygen.py / keygen.c    forward serial generator (shares src/keygen_core.h)
├─ keygen.exe              compiled keygen
├─ dist/
│  └─ KeygenMe.exe         built release binary
├─ public/                 player-facing package
│  ├─ KeygenMe.exe
│  ├─ README.txt           player brief
│  └─ lyknctf.png          banner art
└─ src/                    full source, do not ship
   ├─ crackme.c            GUI + do_check (gates + KDF unlock)
   ├─ keygen_core.h         kg_ksa / kg_state / lykn_keygen / lykn_obf_user
   ├─ sha256.h              self-contained SHA-256
   ├─ flagcrypt.h           lykn_derive_key / lykn_keystream / lykn_tag
   ├─ antidbg.h             lykn_dbg()  (PEB + NtQueryInformationProcess)
   ├─ selfhash.h            lykn_text_hash()  (SHA-256 of own .text)
   ├─ secret_config.h       TARGET_USER + FLAG   (build-only secret!)
   ├─ gen_flag.c            build-time flag encryptor -> flag_enc.h
   ├─ flag_enc.h            generated: g_ct / g_tag / g_encu
   ├─ crackme.rc / crackme.manifest / banner.bmp
   └─ build.ps1             two-pass build + ASLR off + .text verify
```

## Flag

```text
LYKNCTF{k3yg3n_h3ll_s3lfh4sh_4ntidbg_h1dd3n_us3r_2026}
```
