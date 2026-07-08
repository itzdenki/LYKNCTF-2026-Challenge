#!/usr/bin/env python3
"""
Official keygen for LYKNCTF 2026 "Loi Yeu Kho Noi" KeygenMe (v2).
Mirrors keygen_core.h (kg_ksa / kg_state / lykn_keygen).

    usage: python keygen.py <username>

dbg is 0: a keygen targets the CLEAN (non-debugged) program. Under a
debugger the binary feeds dbg!=0 and computes a *different* serial.
"""
import sys

MASK = 0xFFFFFFFF


def ksa():
    key = b"L0i_Y3u_Kh0_N0i"          # 15 bytes
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % 15]) & 0xFF
        S[i], S[j] = S[j], S[i]
    return S


def rotl32(x, r):
    x &= MASK
    return ((x << r) | (x >> (32 - r))) & MASK


def kg_state(u: bytes, dbg: int = 0):
    S = ksa()
    h0 = (0x4C594B4E ^ ((dbg * 0x01010101) & MASK)) & MASK
    h1 = 0x43544632
    h2 = (0x30323600 ^ 0x9E3779B9) & MASK
    h3 = 0xA5A5F00D
    for r in range(3):
        for ch in u:
            c = S[(ch + r * 7) & 0xFF]
            h0 = (rotl32(h0 ^ c, 5) + h1) & MASK
            h1 = (rotl32((h1 + c) & MASK, 11) ^ h2) & MASK
            h2 = (rotl32(h2 ^ ((c * 0x9E3779B1) & MASK), 17) + h3) & MASK
            h3 = (rotl32((h3 + S[h0 & 0xFF]) & MASK, 3) ^ h0) & MASK
    for _ in range(4):
        h0 = (h0 + h3) & MASK
        h1 = (h1 ^ rotl32(h0, 7)) & MASK
        h2 = (h2 + h1) & MASK
        h3 = (h3 ^ rotl32(h2, 13)) & MASK
    return h0, h1, h2, h3


def lykn_key(user: str, dbg: int = 0) -> str:
    u = user.encode("latin-1")
    h0, h1, h2, h3 = kg_state(u, dbg)
    b0 = (h0 >> 16) & 0xFFFF
    b1 = (h0 ^ h1) & 0xFFFF
    b2 = (h1 >> 16) & 0xFFFF
    b3 = (h2 ^ h3) & 0xFFFF
    b4 = ((b0 + b1 + b2 + b3) ^ (h2 >> 16)) & 0xFFFF
    return "-".join("%04X" % b for b in (b0, b1, b2, b3, b4))


def main() -> int:
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} <username>")
        return 1
    user = sys.argv[1]
    if len(user) < 4:
        print("[!] username must be at least 4 characters")
        return 1
    print(f"Username : {user}")
    print(f"License  : {lykn_key(user)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
