#!/usr/bin/env python3
"""Official solver for chall-3.

The checker no longer stores the flag, but its transform is fully invertible.
Everything below is recovered from the binary:

  * kCipher       : the 30-byte constant compared against.
  * kKeyStreamSeed: splitmix64 seed for the per-byte keystream.
  * kSboxSeed     : splitmix64 seed for the Fisher-Yates S-box.
  * kChainIV      : CBC-style chaining IV.
  * pconst(i)     : position constant  (i*37 + 0x5A) & 0xFF.
  * rotate        : rotl8 by (i & 7) per byte.

Running the pipeline backwards over kCipher yields the flag directly -- no
knowledge of the flag string is used anywhere in recover().
"""
import argparse
import subprocess
from pathlib import Path

MASK = (1 << 64) - 1

# --- constants lifted straight out of the binary ---
K_CIPHER = bytes([
    0xEA, 0x43, 0x7A, 0xA1, 0x76, 0x95, 0x48, 0xCE, 0xA7, 0xF3, 0x76, 0x07,
    0x9E, 0x82, 0xC8, 0xAA, 0x45, 0x0A, 0x4D, 0x07, 0x84, 0x22, 0x14, 0x7A,
    0x7E, 0x36, 0xA1, 0x59, 0xF4, 0x12,
])
K_KEYSTREAM_SEED = 0xD1B54A32D192ED03
K_SBOX_SEED      = 0x9E3779B97F4A7C15
K_CHAIN_IV       = 0xA5
CIPHER_LEN = len(K_CIPHER)


def splitmix64(state):
    state = (state + 0x9E3779B97F4A7C15) & MASK
    z = state
    z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & MASK
    z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & MASK
    z ^= z >> 31
    return state, z


def keystream(n, poison=0):
    state = (K_KEYSTREAM_SEED ^ ((poison * 0x100000001B3) & MASK)) & MASK
    out = []
    for _ in range(n):
        state, z = splitmix64(state)
        out.append(z & 0xFF)
    return out


def build_sbox():
    sbox = list(range(256))
    state = K_SBOX_SEED
    for i in range(255, 0, -1):
        state, z = splitmix64(state)
        j = z % (i + 1)
        sbox[i], sbox[j] = sbox[j], sbox[i]
    inv = [0] * 256
    for i, v in enumerate(sbox):
        inv[v] = i
    return sbox, inv


def pconst(i):
    return (i * 37 + 0x5A) & 0xFF


def rotl8(x, r):
    r &= 7
    return x & 0xFF if r == 0 else ((x << r) | (x >> (8 - r))) & 0xFF


def rotr8(x, r):
    r &= 7
    return x & 0xFF if r == 0 else ((x >> r) | (x << (8 - r))) & 0xFF


def encrypt(data, poison=0):
    n = len(data)
    k = keystream(n, poison)
    sbox, _ = build_sbox()
    out = bytearray()
    prev = K_CHAIN_IV
    for i in range(n):
        t = data[i] ^ k[i]
        t = (t + pconst(i)) & 0xFF
        t = rotl8(t, i & 7)
        t = sbox[t]
        t ^= prev
        out.append(t)
        prev = t
    return bytes(out)


def decrypt(cipher, poison=0):
    n = len(cipher)
    k = keystream(n, poison)
    _, inv = build_sbox()
    out = bytearray()
    prev = K_CHAIN_IV
    for i in range(n):
        e = cipher[i] ^ prev
        d = inv[e]
        b = rotr8(d, i & 7)
        a = (b - pconst(i)) & 0xFF
        out.append(a ^ k[i])
        prev = cipher[i]
    return bytes(out)


def recover():
    """Invert kCipher -> flag. No flag string is used here."""
    return decrypt(K_CIPHER).decode()


def check_candidate(candidate):
    return encrypt(candidate.encode()) == K_CIPHER


def run_binary(path, flag):
    if not path.exists():
        return None
    try:
        result = subprocess.run(
            [str(path), flag],
            cwd=path.parent,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as exc:
        return "skip", exc.strerror or str(exc)
    return result.returncode, result.stdout.strip()


def main():
    parser = argparse.ArgumentParser(description="Official solver for chall-3.")
    parser.add_argument("--check", metavar="FLAG", help="check a candidate against the reimplemented checker")
    parser.add_argument("--verify-bin", action="store_true", help="run local dist binaries with the recovered flag")
    args = parser.parse_args()

    if args.check is not None:
        print("Correct!" if check_candidate(args.check) else "Nope")
        return

    flag = recover()
    print(flag)
    assert check_candidate(flag), "recovered flag does not round-trip!"

    if args.verify_bin:
        root = Path(__file__).resolve().parent
        for rel in ("dist/chall-3.exe", "dist/chall-3"):
            result = run_binary(root / rel, flag)
            if result is None:
                print(f"{rel}: missing")
            else:
                code, output = result
                if code == "skip":
                    print(f"{rel}: skipped ({output})")
                else:
                    print(f"{rel}: exit={code} output={output}")


if __name__ == "__main__":
    main()
