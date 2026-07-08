#!/usr/bin/env python3
"""
Full offline solver for LYKNCTF 2026 chall7 "License Activation".

From the binary alone it:
  1. parses the PE and hashes .text like the in-binary self-hash
     (VirtualSize bytes at PointerToRawData; ASLR is disabled so on-disk ==
      in-memory), with dbg = 0 (clean run),
  2. derives the bytecode decode key K = SHA256(text_hash || 0 || salt) and
     the CTR keystream, then SCANS the image for the 183-byte encrypted
     program (it decodes to a program starting `LDIN R0,0` and ending HALT),
  3. disassembles that program to recover the ARX constants
     (SEED, DELTA, ROUNDS, rotation schedule),
  4. finds the 32-byte target and runs the ARX *backwards* to recover the
     32 plaintext bytes = the flag.

    usage: python solve.py <Activator.exe>

The VM salt (0x4C594B37) is read straight out of vm_decode in the binary.
"""
import sys
import struct
import hashlib

MASK = 0xFFFFFFFF
SALT = 0x4C594B37          # VM_SALT, visible in vm_decode()
PROG_LEN = 183             # visible in do_check / vm_program.h


def rol(x, r): x &= MASK; r &= 31; return ((x << r) | (x >> (32 - r))) & MASK if r else x
def ror(x, r): x &= MASK; r &= 31; return ((x >> r) | (x << (32 - r))) & MASK if r else x


def sections(data):
    e = struct.unpack_from("<I", data, 0x3C)[0]
    nsec = struct.unpack_from("<H", data, e + 6)[0]
    optsz = struct.unpack_from("<H", data, e + 20)[0]
    tbl = e + 24 + optsz
    for i in range(nsec):
        o = tbl + i * 40
        name = data[o:o + 8].rstrip(b"\x00").decode("latin1")
        vsize, vaddr, rawsz, rawptr = struct.unpack_from("<IIII", data, o + 8)
        yield name, vsize, vaddr, rawsz, rawptr


def text_hash(data):
    for name, vsize, vaddr, rawsz, rawptr in sections(data):
        if name == ".text":
            return hashlib.sha256(data[rawptr:rawptr + vsize]).digest()
    raise RuntimeError(".text not found")


def keystream(K, n):
    out = b""
    i = 0
    while len(out) < n:
        out += hashlib.sha256(K + struct.pack("<I", i)).digest()
        i += 1
    return out[:n]


def disasm_constants(p):
    """Extract SEED, DELTA, ROUNDS, ROT[] from the decoded program."""
    seed = delta = rounds = None
    rot = []
    i = 0
    while i < len(p):
        op = p[i]
        if op == 0x11:               # LDI reg, imm32
            reg = p[i + 1]; imm = struct.unpack_from("<I", p, i + 2)[0]
            if reg == 9: seed = imm
            if reg == 8: rounds = imm
            i += 6
        elif op == 0x99:             # ADDI reg, imm32
            reg = p[i + 1]; imm = struct.unpack_from("<I", p, i + 2)[0]
            if reg == 9: delta = imm
            i += 6
        elif op == 0xAA:             # XORI
            i += 6
        elif op == 0xBB:             # ROL reg, amt
            rot.append(p[i + 2]); i += 3
        elif op in (0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0xCC):
            i += 3
        elif op == 0xDD:
            i += 2
        elif op in (0xEE, 0xE0):
            i += 4
        elif op == 0xF0:
            i += 3
        elif op == 0xFF:
            break
        else:
            i += 1
    return seed, delta, rounds, rot[:8]


def arx_inverse(state, seed, delta, rounds, rot):
    s = list(state)
    ks = [(seed + r * delta) & MASK for r in range(rounds)]
    for r in range(rounds - 1, -1, -1):
        k = ks[r]
        for i in range(7, -1, -1):
            s[i] ^= s[(i + 1) & 7]
            s[i] = ror(s[i], rot[i])
            s[i] = (s[i] - k) & MASK
    return s


def main():
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} <Activator.exe>")
        return 1
    data = open(sys.argv[1], "rb").read()

    th = text_hash(data)
    K = hashlib.sha256(th + b"\x00" + struct.pack("<I", SALT)).digest()
    ks = keystream(K, PROG_LEN)
    print(f"[*] text_hash = {th.hex()}")

    # 1) locate + decode the bytecode program
    prog = None
    for name, vsize, vaddr, rawsz, rawptr in sections(data):
        blob = data[rawptr:rawptr + rawsz]
        for off in range(0, max(0, len(blob) - PROG_LEN) + 1):
            cand = bytes(c ^ k for c, k in zip(blob[off:off + PROG_LEN], ks))
            if cand[0] == 0x22 and cand[1] == 0x00 and cand[-1] == 0xFF:
                prog = cand
                print(f"[+] bytecode found in {name} @ raw+0x{off:X}")
                break
        if prog:
            break
    if not prog:
        print("[!] could not decode bytecode (wrong text_hash/salt?)")
        return 1

    seed, delta, rounds, rot = disasm_constants(prog)
    print(f"[+] SEED=0x{seed:08X} DELTA=0x{delta:08X} ROUNDS={rounds} ROT={rot}")

    # 2) find the 32-byte target -> invert -> printable flag
    for name, vsize, vaddr, rawsz, rawptr in sections(data):
        blob = data[rawptr:rawptr + rawsz]
        for off in range(0, max(0, len(blob) - 32) + 1):
            w = list(struct.unpack_from("<8I", blob, off))
            inv = arx_inverse(w, seed, delta, rounds, rot)
            pt = struct.pack("<8I", *inv)
            if all(0x20 <= b <= 0x7E for b in pt):
                print(f"[+] target in {name} @ raw+0x{off:X}")
                print(f"[+] FLAG: LYKNCTF{{{pt.decode('latin1')}}}")
                return 0
    print("[!] target not found")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
