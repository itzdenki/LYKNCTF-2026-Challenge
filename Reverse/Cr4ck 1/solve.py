#!/usr/bin/env python3
"""
Full offline solver for LYKNCTF 2026 "Loi Yeu Kho Noi" KeygenMe (v2).

Given ONLY the binary and the recovered hidden username, this:
  1. parses the PE and hashes .text exactly like the in-binary self-hash
     (VirtualSize bytes at PointerToRawData; the build disables ASLR so
      the on-disk .text equals the in-memory .text),
  2. re-implements the keygen to get the serial for that user,
  3. derives K = SHA256(user || 0x1F || serial || 0x1F || text_hash || 0),
  4. builds the CTR keystream and SCANS .rdata for the 96-byte ciphertext
     whose decryption starts with 'LYKNCTF{' -- no need to know where g_ct
     lives.

    usage: python solve.py <KeygenMe.exe> <hidden_username>

The hidden username itself is recovered by reversing lykn_obf_user (the
KSA S-box XOR) on the g_encu blob -- see WRITEUP.md.
"""
import sys
import struct
import hashlib

from keygen import lykn_key          # shared keygen (dbg=0)

FLAG_CTLEN = 96


def sections(data):
    e = struct.unpack_from("<I", data, 0x3C)[0]
    nsec = struct.unpack_from("<H", data, e + 6)[0]
    optsz = struct.unpack_from("<H", data, e + 20)[0]
    tbl = e + 24 + optsz
    out = []
    for i in range(nsec):
        o = tbl + i * 40
        name = data[o:o + 8].rstrip(b"\x00").decode("latin1")
        vsize, vaddr, rawsz, rawptr = struct.unpack_from("<IIII", data, o + 8)
        out.append((name, vsize, vaddr, rawsz, rawptr))
    return out


def text_hash(data):
    for name, vsize, vaddr, rawsz, rawptr in sections(data):
        if name == ".text":
            return hashlib.sha256(data[rawptr:rawptr + vsize]).digest()
    raise RuntimeError(".text not found")


def derive_key(user, serial, th, dbg=0):
    m = hashlib.sha256()
    m.update(user.encode("latin1")); m.update(b"\x1f")
    m.update(serial.encode("latin1")); m.update(b"\x1f")
    m.update(th); m.update(bytes([dbg]))
    return m.digest()


def keystream(K):
    ks = b""
    for i in range(FLAG_CTLEN // 32):
        ks += hashlib.sha256(K + struct.pack("<I", i)).digest()
    return ks


def main():
    if len(sys.argv) < 3:
        print(f"usage: {sys.argv[0]} <KeygenMe.exe> <hidden_username>")
        return 1
    path, user = sys.argv[1], sys.argv[2]
    data = open(path, "rb").read()

    th = text_hash(data)
    serial = lykn_key(user)                      # dbg = 0
    K = derive_key(user, serial, th)
    ks = keystream(K)

    print(f"[*] user       : {user}")
    print(f"[*] serial     : {serial}")
    print(f"[*] text_hash  : {th.hex()}")

    # scan every section's raw bytes for the ciphertext window
    for name, vsize, vaddr, rawsz, rawptr in sections(data):
        blob = data[rawptr:rawptr + rawsz]
        for off in range(0, max(0, len(blob) - FLAG_CTLEN) + 1):
            pt = bytes(c ^ k for c, k in zip(blob[off:off + FLAG_CTLEN], ks))
            if pt.startswith(b"LYKNCTF{"):
                nul = pt.find(b"\x00")
                flag = pt[:nul if nul >= 0 else FLAG_CTLEN].decode("latin1")
                print(f"[+] found ciphertext in {name} @ raw+0x{off:X}")
                print(f"[+] FLAG: {flag}")
                return 0
    print("[!] ciphertext not found (wrong username? patched/ASLR binary?)")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
