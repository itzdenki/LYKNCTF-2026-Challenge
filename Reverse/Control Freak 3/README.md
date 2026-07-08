# Control Freak 3

## Challenge shape

`chall-4` is a custom-only reverse challenge. The player-facing interface stays simple:

```text
flag: 
Correct!
Nope
```

The release package should contain stripped Windows and Linux binaries only. Do not ship
`gen.cpp`, `solve.py`, or this writeup until the post-contest/bounty drop.

## Architecture

The checker no longer compares a visible hash target. The real validation program is an
encrypted bytecode blob interpreted by a custom VM:

- 5 encrypted VM blocks, decrypted one block at a time from a runtime guard state.
- Permuted opcode bytes decoded through an encoded dispatch table.
- Macro handlers for length, byte, pair, triple, global, and noise instructions.
- 77 real constraint instructions mixed with noise handlers.
- Constraint graph couples adjacent and cross-position flag bytes, then finishes with
  global ARX-style checks.

The VM accumulator ORs every failed constraint. There is no early branch revealing which
condition failed.

## Anti-analysis

Anti-analysis does not crash on detection. It poisons the VM accumulator so even the real
flag prints `Nope` under suspicious conditions.

Windows probes:

- `IsDebuggerPresent`
- `CheckRemoteDebuggerPresent`
- PEB `BeingDebugged`
- PEB `NtGlobalFlag`
- dynamic `NtQueryInformationProcess`
- hardware debug registers

Linux probes:

- `/proc/self/status` / `TracerPid`
- `ptrace(PTRACE_TRACEME)`
- `LD_PRELOAD` / `LD_AUDIT`
- `/proc/self/maps` scan for common instrumentation
- `SIGTRAP` handler sanity check

The sensitive strings are decoded at runtime to reduce obvious `strings` output.

## Intended solve

The intended path is:

1. Bypass or neutralize the poisoned anti-analysis path.
2. Locate the encrypted VM blob and block metadata.
3. Rebuild the opcode permutation.
4. Decrypt each block using the guard update schedule.
5. Lift VM instructions into a small IR.
6. Recover the flag by solving the byte/pair/triple/global constraints.

The private solver implements this path by parsing `gen.cpp`, decrypting the VM, dumping IR
when requested, and recovering the flag with constraint propagation/MITM.

```bash
python solve.py --dump-ir
python solve.py
python solve.py --check 'LYKNCTF{0UT_0F_C0NTR0L_VM2026}'
python solve.py --verify-bin
```

## Staged release hints

- Stage 0: binaries only.
- Stage 1, after 3-5 days if needed: "The wrong environment can make the right flag wrong."
- Stage 2, after 7-10 days if needed: "The checker is a small VM; adjacent bytes are not checked independently."
- Stage 3: publish source, solver, build seed, and full writeup.

## Flag

```text
LYKNCTF{0UT_0F_C0NTR0L_VM2026}
```
