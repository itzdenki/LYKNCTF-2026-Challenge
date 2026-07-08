#!/usr/bin/env python3
"""
Assembler + reference emulator + target generator for chall7's VM.

Single source of truth for the VM ISA and the ARX program. It:
  * assembles the ARX permutation program into bytecode,
  * emulates it (reference for the C interpreter in vm.h),
  * implements arx_forward / arx_inverse (readable reference),
  * computes target = ARX_permute(flag_inner),
  * optionally XOR-encrypts the bytecode with the runtime decode key
    (SHA256(text_hash || dbg || salt)),
  * emits src/vm_program.h.

    usage: python asm.py [pass1.exe]
       (no arg -> dummy zero text-hash; with arg -> real encrypted bytecode)
"""
import os
import re
import sys
import struct
import hashlib

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "..", "src")
MASK = 0xFFFFFFFF

# ---- ISA -----------------------------------------------------------------
OPS = {
    "LDI": 0x11, "LDIN": 0x22, "LDT": 0x33, "MOV": 0x44,
    "ADD": 0x55, "SUB": 0x66, "XOR": 0x77, "MUL": 0x88,
    "ADDI": 0x99, "XORI": 0xAA, "ROL": 0xBB, "ROR": 0xCC,
    "ACC": 0xDD, "JNZ": 0xEE, "DJNZ": 0xE0, "JMP": 0xF0, "HALT": 0xFF,
}

SEED = 0x1BADC0DE
DELTA = 0x9E3779B9
ROUNDS = 32
ROT = [7, 9, 13, 18, 3, 11, 17, 5]


def rol(x, r): x &= MASK; return ((x << r) | (x >> (32 - r))) & MASK
def ror(x, r): x &= MASK; return ((x >> r) | (x << (32 - r))) & MASK


# ---- assembler -----------------------------------------------------------
ISIZE = {
    "LDI": 6, "ADDI": 6, "XORI": 6,
    "LDIN": 3, "LDT": 3, "MOV": 3, "ADD": 3, "SUB": 3, "XOR": 3, "MUL": 3,
    "ROL": 3, "ROR": 3, "ACC": 2, "JNZ": 4, "DJNZ": 4, "JMP": 3, "HALT": 1,
}


def assemble(lines):
    def reg(a): assert a[0].upper() == "R"; return int(a[1:])
    def imm(a): return int(a, 0) & MASK

    # pass 1: record label offsets
    labels, pc, prog = {}, 0, []
    for ln in lines:
        ln = ln.split(";")[0].strip()
        if not ln:
            continue
        if ln.endswith(":"):
            labels[ln[:-1]] = pc
            continue
        parts = ln.replace(",", " ").split()
        op = parts[0].upper()
        prog.append((op, parts[1:], pc))
        pc += ISIZE[op]
    total = pc

    # pass 2: emit
    out = bytearray()
    for op, args, pc in prog:
        out.append(OPS[op])
        if op in ("LDI", "ADDI", "XORI"):
            out.append(reg(args[0])); out += struct.pack("<I", imm(args[1]))
        elif op in ("LDIN", "LDT"):
            out.append(reg(args[0])); out.append(int(args[1], 0) & 0xFF)
        elif op in ("MOV", "ADD", "SUB", "XOR", "MUL"):
            out.append(reg(args[0])); out.append(reg(args[1]))
        elif op in ("ROL", "ROR"):
            out.append(reg(args[0])); out.append(int(args[1], 0) & 0xFF)
        elif op == "ACC":
            out.append(reg(args[0]))
        elif op in ("JNZ", "DJNZ"):
            rel = labels[args[1]] - (pc + 4)
            out.append(reg(args[0])); out += struct.pack("<h", rel)
        elif op == "JMP":
            rel = labels[args[0]] - (pc + 3)
            out += struct.pack("<h", rel)
        elif op == "HALT":
            pass
        else:
            raise ValueError(op)
    assert len(out) == total, (len(out), total)
    return bytes(out)


def build_program():
    L = []
    for i in range(8):
        L.append(f"LDIN R{i}, {i}")
    L.append(f"LDI R9, 0x{SEED:08X}")
    L.append(f"LDI R8, {ROUNDS}")
    L.append("round:")
    for i in range(8):
        L.append(f"ADD R{i}, R9")
        L.append(f"ROL R{i}, {ROT[i]}")
        L.append(f"XOR R{i}, R{(i + 1) & 7}")
    L.append(f"ADDI R9, 0x{DELTA:08X}")
    L.append("DJNZ R8, round")
    for i in range(8):
        L.append(f"LDT R10, {i}")
        L.append(f"XOR R10, R{i}")
        L.append("ACC R10")
    L.append("HALT")
    return assemble(L)


# ---- reference ARX (readable) --------------------------------------------
def arx_forward(state):
    s = list(state); k = SEED
    for _ in range(ROUNDS):
        for i in range(8):
            s[i] = (s[i] + k) & MASK
            s[i] = rol(s[i], ROT[i])
            s[i] ^= s[(i + 1) & 7]
        k = (k + DELTA) & MASK
    return s


def arx_inverse(state):
    s = list(state)
    ks = [(SEED + r * DELTA) & MASK for r in range(ROUNDS)]
    for r in range(ROUNDS - 1, -1, -1):
        k = ks[r]
        for i in range(7, -1, -1):
            s[i] ^= s[(i + 1) & 7]
            s[i] = ror(s[i], ROT[i])
            s[i] = (s[i] - k) & MASK
    return s


# ---- emulator (mirrors vm.h) ---------------------------------------------
def vm_execute(prog, inw, target):
    R = [0] * 16; acc = 0; pc = 0
    def rd32(p): return struct.unpack_from("<I", prog, p)[0]
    while True:
        op = prog[pc]; pc += 1
        if op == 0x11:   r = prog[pc]; R[r] = rd32(pc + 1); pc += 5
        elif op == 0x22: r = prog[pc]; R[r] = inw[prog[pc + 1]] & MASK; pc += 2
        elif op == 0x33: r = prog[pc]; R[r] = target[prog[pc + 1]] & MASK; pc += 2
        elif op == 0x44: R[prog[pc]] = R[prog[pc + 1]]; pc += 2
        elif op == 0x55: R[prog[pc]] = (R[prog[pc]] + R[prog[pc + 1]]) & MASK; pc += 2
        elif op == 0x66: R[prog[pc]] = (R[prog[pc]] - R[prog[pc + 1]]) & MASK; pc += 2
        elif op == 0x77: R[prog[pc]] ^= R[prog[pc + 1]]; pc += 2
        elif op == 0x88: R[prog[pc]] = (R[prog[pc]] * R[prog[pc + 1]]) & MASK; pc += 2
        elif op == 0x99: r = prog[pc]; R[r] = (R[r] + rd32(pc + 1)) & MASK; pc += 5
        elif op == 0xAA: r = prog[pc]; R[r] ^= rd32(pc + 1); pc += 5
        elif op == 0xBB: R[prog[pc]] = rol(R[prog[pc]], prog[pc + 1]); pc += 2
        elif op == 0xCC: R[prog[pc]] = ror(R[prog[pc]], prog[pc + 1]); pc += 2
        elif op == 0xDD: acc |= R[prog[pc]]; pc += 1
        elif op == 0xEE:
            r = prog[pc]; rel = struct.unpack_from("<h", prog, pc + 1)[0]; pc += 3
            if R[r] != 0: pc += rel
        elif op == 0xE0:
            r = prog[pc]; rel = struct.unpack_from("<h", prog, pc + 1)[0]; pc += 3
            R[r] = (R[r] - 1) & MASK
            if R[r] != 0: pc += rel
        elif op == 0xF0:
            rel = struct.unpack_from("<h", prog, pc)[0]; pc += 2; pc += rel
        elif op == 0xFF:
            break
        else:
            raise ValueError(f"bad op 0x{op:02X} at {pc-1}")
    return acc & MASK


# ---- helpers -------------------------------------------------------------
def words_from_bytes(b):
    assert len(b) == 32
    return list(struct.unpack("<8I", b))


def read_flag():
    txt = open(os.path.join(SRC, "secret_config.h")).read()
    m = re.search(r'FLAG_TEXT\s+"([^"]*)"', txt)
    flag = m.group(1)
    inner = flag[flag.index("{") + 1:flag.index("}")]
    assert len(inner) == 32, f"inner must be 32 bytes, got {len(inner)}"
    return flag, inner


def text_hash_of(path):
    data = open(path, "rb").read()
    e = struct.unpack_from("<I", data, 0x3C)[0]
    nsec = struct.unpack_from("<H", data, e + 6)[0]
    optsz = struct.unpack_from("<H", data, e + 20)[0]
    tbl = e + 24 + optsz
    for i in range(nsec):
        o = tbl + i * 40
        if data[o:o + 8].rstrip(b"\x00") == b".text":
            vsize, vaddr, rawsz, rawptr = struct.unpack_from("<IIII", data, o + 8)
            return hashlib.sha256(data[rawptr:rawptr + vsize]).digest()
    raise RuntimeError(".text not found")


SALT = 0x4C594B37  # 'LYK7'


def decode_key(text_hash, dbg):
    m = hashlib.sha256()
    m.update(text_hash); m.update(bytes([dbg])); m.update(struct.pack("<I", SALT))
    return m.digest()


def keystream(K, n):
    out = b""
    i = 0
    while len(out) < n:
        out += hashlib.sha256(K + struct.pack("<I", i)).digest()
        i += 1
    return out[:n]


def emit_c_array(name, data, per=12):
    s = f"static const unsigned char {name}[{len(data)}] = {{\n    "
    for i, b in enumerate(data):
        s += "0x%02X," % b
        s += "\n    " if (i + 1) % per == 0 else " "
    return s.rstrip() + "\n};\n"


def main():
    flag, inner = read_flag()
    inw = words_from_bytes(inner.encode("latin1"))
    target = arx_forward(inw)

    prog = build_program()

    # self-tests
    assert vm_execute(prog, inw, target) == 0, "VM must accept the real flag"
    assert arx_inverse(target) == inw, "inverse must recover the flag"
    import random
    bad = 0
    for _ in range(200):
        r = [random.randrange(1 << 32) for _ in range(8)]
        if vm_execute(prog, r, target) == 0:
            bad += 1
    assert bad == 0, "random input wrongly accepted"

    # text hash / encryption
    text_hash = b"\x00" * 32
    mode = "DUMMY(zero-hash)"
    if len(sys.argv) >= 2:
        text_hash = text_hash_of(sys.argv[1]); mode = "REAL"
    K = decode_key(text_hash, 0)
    ks = keystream(K, len(prog))
    prog_enc = bytes(a ^ b for a, b in zip(prog, ks))

    tgt_bytes = struct.pack("<8I", *target)

    out = os.path.join(SRC, "vm_program.h")
    with open(out, "w") as f:
        f.write("/* Auto-generated by tools/asm.py. DO NOT hand-edit. */\n")
        f.write("#ifndef VM_PROGRAM_H\n#define VM_PROGRAM_H\n\n")
        f.write("#define PROG_LEN %d\n" % len(prog))
        f.write("#define VM_SALT 0x%08XU\n\n" % SALT)
        f.write(emit_c_array("g_prog_enc", prog_enc) + "\n")
        f.write(emit_c_array("g_target_b", tgt_bytes) + "\n")
        # plaintext program kept ONLY for the parity harness build (never
        # compiled into the shipped crackme); guarded by VM_HARNESS.
        f.write("#ifdef VM_HARNESS\n")
        f.write(emit_c_array("g_prog_plain", prog))
        f.write("#endif\n\n")
        f.write("#endif /* VM_PROGRAM_H */\n")

    print(f"[asm] {mode}  inner='{inner}' PROG_LEN={len(prog)}")
    print(f"[asm] target = {tgt_bytes.hex()}")
    print(f"[asm] text_hash[0:4] = {text_hash[:4].hex()}")
    print(f"[asm] self-tests OK (flag accepted, inverse ok, 200 random rejected)")


if __name__ == "__main__":
    main()
