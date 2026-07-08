#!/usr/bin/env python3
import argparse
import re
import struct
import subprocess
from pathlib import Path


MASK32 = (1 << 32) - 1
MASK64 = (1 << 64) - 1
BASE_GUARD = 0x8F4D2C6B1A097835

OP_NAMES = {
    0: "HALT",
    1: "END",
    2: "LEN",
    3: "BYTE",
    4: "PAIR",
    5: "TRI",
    6: "GLOBAL",
    7: "NOISE",
}


def rotl32(x, r):
    r &= 31
    x &= MASK32
    return ((x << r) | (x >> (32 - r))) & MASK32 if r else x


def rotl64(x, r):
    r &= 63
    x &= MASK64
    return ((x << r) | (x >> (64 - r))) & MASK64 if r else x


def stream_byte(state, i):
    state[0] = (state[0] + 0x9E3779B97F4A7C15 + i) & MASK64
    z = state[0]
    z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & MASK64
    z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & MASK64
    z ^= z >> 31
    return (z >> ((i & 7) * 8)) & 0xFF


def byte_mix(x, idx, seed):
    x &= 0xFF
    idx &= 0xFF
    seed &= MASK32
    v = (x | (idx << 8)) ^ ((seed + 0x9E3779B9) & MASK32)
    v = rotl32((v * 0x45D9F3B + ((x << ((idx & 3) + 1)) & MASK32)) & MASK32,
               ((seed >> 27) & 15) + 5)
    v ^= v >> 11
    v = (v * 0x27D4EB2D) & MASK32
    v ^= rotl32(((x * 0x165667B1) + idx + seed) & MASK32, ((x ^ seed) & 7) + 3)
    return v & MASK32


def pair_mix(a, b, i, j, seed):
    a &= 0xFF
    b &= 0xFF
    i &= 0xFF
    j &= 0xFF
    seed &= MASK32
    v = (seed ^ ((i * 0x9E3779B1) & MASK32) ^ ((j * 0x85EBCA77) & MASK32)) & MASK32
    v = (v + ((a + 0x101) * ((seed | 1) & MASK32))) & MASK32
    v = rotl32(v ^ (((b + 0x51) * 0xC2B2AE3D) & MASK32), ((seed ^ (i << 1) ^ j) & 15) + 5)
    v = (v + (((a ^ b) + 0x33) * 0x27D4EB2D)) & MASK32
    v ^= rotl32(((a + (b << 8) + i * 17 + j * 29) * 0x165667B1) & MASK32,
                 ((seed >> 5) & 15) + 3)
    v = (v + (((a * b + 0x9E37) & MASK32) * (((seed >> 16) | 1) & MASK32))) & MASK32
    v ^= v >> 13
    v = (v * 0x85EBCA6B) & MASK32
    v ^= v >> 16
    return v & MASK32


def tri_mix(a, b, c, i, j, k, seed):
    a &= 0xFF
    b &= 0xFF
    c &= 0xFF
    i &= 0xFF
    j &= 0xFF
    k &= 0xFF
    seed &= MASK32
    v = (seed + ((i + 1) * 0x7F4A7C15) + ((j + 3) * 0x94D049BB) + ((k + 5) * 0xD6E8FEB9)) & MASK32
    v ^= ((a + 0x21) * (b + 0x35) * 0x45D9F3B) & MASK32
    v = rotl32(v, ((seed >> 11) & 15) + 7)
    v = (v + (((b ^ c) + 0x123) * 0x27D4EB2D)) & MASK32
    v ^= rotl32(((a << 16) ^ (b << 8) ^ c ^ seed) & MASK32, ((i + j + k) & 15) + 3)
    v = (v + (((a * c + b * 0x101 + 0xBEEF) & MASK32) * 0x165667B1)) & MASK32
    v ^= v >> 15
    v = (v * 0xC2B2AE35) & MASK32
    v ^= v >> 16
    return v & MASK32


def global_mix(data, seed):
    seed &= MASK32
    length = len(data)
    s = (0x243F6A8885A308D3 ^ ((length * 0x9E3779B97F4A7C15) & MASK64) ^ seed) & MASK64
    t = (0x13198A2E03707344 ^ rotl64(seed | 1, 29)) & MASK64
    for p in range(3):
        for i in range(64):
            ch = data[i] if i < length else ((0xA7 ^ i * 31 ^ p * 17 ^ length) & 0xFF)
            lane = ch | ((i + p * 67) << 8) | ((length & 0xFF) << 24)
            s = (rotl64(s ^ lane ^ t, ((i + p) & 31) + 5) * 0x100000001B3 + ch + seed + p) & MASK64
            t ^= rotl64((s + ((ch + 0x101) * 0xD6E8FEB86659FD93)) & MASK64, ((ch ^ i ^ seed) & 31) + 1)
            t = (t * 0x94D049BB133111EB + i + p) & MASK64
        s ^= rotl64(t, 17 + p * 9)
        s &= MASK64
    return (s ^ rotl64(t, 23) ^ ((length * 0xBF58476D1CE4E5B9) & MASK64)) & MASK64


def parse_num(token):
    token = token.strip().lower()
    token = re.sub(r"(ull|llu|ll|ul|u|l)$", "", token)
    return int(token, 0)


def parse_byte_array(source, name):
    m = re.search(rf"static const unsigned char {name}\[[^\]]*\]\s*=\s*\{{(.*?)\}};", source, re.S)
    if not m:
        raise ValueError(f"missing array {name}")
    return bytes(parse_num(x) for x in re.findall(r"0x[0-9a-fA-F]+|\d+", m.group(1)))


def parse_meta(source):
    m = re.search(r"static const BlockMeta kBlockMeta\[\]\s*=\s*\{(.*?)\};", source, re.S)
    if not m:
        raise ValueError("missing kBlockMeta")
    metas = []
    for row in re.findall(r"\{([^{}]+)\}", m.group(1)):
        nums = [parse_num(x) for x in re.findall(r"0x[0-9a-fA-F]+(?:ull|u|ll|l)?|\d+", row)]
        if len(nums) == 5:
            metas.append(tuple(nums))
    if not metas:
        raise ValueError("no block metadata parsed")
    return metas


def load_program(source_path):
    source = Path(source_path).read_text(encoding="utf-8")
    return {
        "opdecode": parse_byte_array(source, "kOpDecodeEnc"),
        "blob": parse_byte_array(source, "kVmBlob"),
        "metas": parse_meta(source),
    }


def decrypt_blocks(program):
    blob = program["blob"]
    guard = BASE_GUARD
    blocks = []
    for block_id, (offset, size, key, salt, mac) in enumerate(program["metas"]):
        stream = key ^ rotl64((guard + salt + (block_id + 1) * 0xD6E8FEB86659FD93) & MASK64,
                              ((block_id * 11) & 63) + 1)
        state = [stream]
        out = bytearray()
        for i, enc in enumerate(blob[offset:offset + size]):
            mask = stream_byte(state, i) ^ ((i * 29 + block_id * 17 + ((guard >> ((i & 7) * 8)) & 0xFF)) & 0xFF)
            out.append(enc ^ mask)
        blocks.append(bytes(out))
        guard = rotl64((guard ^ mac ^ ((block_id + 1) * 0x9E3779B97F4A7C15)) & MASK64,
                       ((block_id + 3) * 7) & 63)
    return blocks


def decode_opcode(opdecode, raw):
    return opdecode[raw] ^ ((raw * 37 + 0x5A) & 0xFF)


def read_u32(block, ip):
    return struct.unpack_from("<I", block, ip)[0], ip + 4


def read_u64(block, ip):
    return struct.unpack_from("<Q", block, ip)[0], ip + 8


def disassemble(program):
    blocks = decrypt_blocks(program)
    ir = []
    for block_id, block in enumerate(blocks):
        ip = 0
        while ip < len(block):
            raw = block[ip]
            ip += 1
            op = decode_opcode(program["opdecode"], raw)
            name = OP_NAMES.get(op, f"BAD_{op:02x}")
            if name in ("HALT", "END"):
                ir.append((block_id, name))
                break
            if name == "LEN":
                target, ip = read_u32(block, ip)
                seed, ip = read_u32(block, ip)
                ir.append((block_id, name, target, seed))
            elif name == "BYTE":
                idx = block[ip]
                ip += 1
                target, ip = read_u32(block, ip)
                seed, ip = read_u32(block, ip)
                ir.append((block_id, name, idx, target, seed))
            elif name == "PAIR":
                i, j = block[ip], block[ip + 1]
                ip += 2
                target, ip = read_u32(block, ip)
                seed, ip = read_u32(block, ip)
                ir.append((block_id, name, i, j, target, seed))
            elif name == "TRI":
                i, j, k = block[ip], block[ip + 1], block[ip + 2]
                ip += 3
                target, ip = read_u32(block, ip)
                seed, ip = read_u32(block, ip)
                ir.append((block_id, name, i, j, k, target, seed))
            elif name == "GLOBAL":
                target, ip = read_u64(block, ip)
                seed, ip = read_u32(block, ip)
                ir.append((block_id, name, target, seed))
            elif name == "NOISE":
                salt, ip = read_u32(block, ip)
                ir.append((block_id, name, salt))
            else:
                raise ValueError(f"bad opcode {op:#x} in block {block_id} at {ip - 1:#x}")
    return ir


def candidate_byte(data, idx):
    return data[idx] if idx < len(data) else ((0xA5 ^ idx * 17 ^ len(data)) & 0xFF)


def check_ir(ir, candidate):
    data = candidate.encode() if isinstance(candidate, str) else bytes(candidate)
    acc = 0
    halted = False
    for ins in ir:
        name = ins[1]
        if name == "HALT":
            halted = True
            break
        if name in ("END", "NOISE"):
            continue
        if name == "LEN":
            _, _, target, seed = ins
            n = len(data)
            v = rotl32((((n ^ seed) * 0x45D9F3B) + (n << 8) + 0x9E3779B9) & MASK32,
                       ((seed >> 27) & 7) + 5) ^ (seed >> 3)
            acc |= (v ^ target) & MASK32
        elif name == "BYTE":
            _, _, idx, target, seed = ins
            acc |= byte_mix(candidate_byte(data, idx), idx, seed) ^ target
        elif name == "PAIR":
            _, _, i, j, target, seed = ins
            acc |= pair_mix(candidate_byte(data, i), candidate_byte(data, j), i, j, seed) ^ target
        elif name == "TRI":
            _, _, i, j, k, target, seed = ins
            acc |= tri_mix(candidate_byte(data, i), candidate_byte(data, j), candidate_byte(data, k), i, j, k, seed) ^ target
        elif name == "GLOBAL":
            _, _, target, seed = ins
            acc |= global_mix(data, seed) ^ target
    return halted and acc == 0


def infer_length(ir):
    answers = []
    len_constraints = [ins for ins in ir if ins[1] == "LEN"]
    for n in range(1, 128):
        ok = True
        for _, _, target, seed in len_constraints:
            v = rotl32((((n ^ seed) * 0x45D9F3B) + (n << 8) + 0x9E3779B9) & MASK32,
                       ((seed >> 27) & 7) + 5) ^ (seed >> 3)
            if (v ^ target) & MASK32:
                ok = False
                break
        if ok:
            answers.append(n)
    if len(answers) != 1:
        raise ValueError(f"ambiguous length candidates: {answers}")
    return answers[0]


def recover_flag(ir, charset):
    length = infer_length(ir)
    domains = [set(charset) for _ in range(length)]
    byte_constraints = [ins for ins in ir if ins[1] == "BYTE"]
    pair_constraints = [ins for ins in ir if ins[1] == "PAIR"]
    tri_constraints = [ins for ins in ir if ins[1] == "TRI"]

    for _, _, idx, target, seed in byte_constraints:
        if idx < length:
            domains[idx] = {x for x in domains[idx] if byte_mix(x, idx, seed) == target}
            if not domains[idx]:
                raise ValueError(f"empty domain at index {idx}")

    by_pos = [[] for _ in range(length)]
    for ins in pair_constraints + tri_constraints:
        for idx in ins[2:-2]:
            if idx < length:
                by_pos[idx].append(ins)

    assigned = [None] * length
    solutions = []

    def constraint_ok(ins):
        name = ins[1]
        if name == "PAIR":
            _, _, i, j, target, seed = ins
            if i >= length or j >= length or assigned[i] is None or assigned[j] is None:
                return True
            return pair_mix(assigned[i], assigned[j], i, j, seed) == target
        if name == "TRI":
            _, _, i, j, k, target, seed = ins
            if i >= length or j >= length or k >= length:
                return True
            if assigned[i] is None or assigned[j] is None or assigned[k] is None:
                return True
            return tri_mix(assigned[i], assigned[j], assigned[k], i, j, k, seed) == target
        return True

    def dfs(pos):
        if len(solutions) > 1:
            return
        if pos == length:
            data = bytes(assigned)
            if check_ir(ir, data):
                solutions.append(data.decode("ascii"))
            return
        for value in sorted(domains[pos]):
            assigned[pos] = value
            if all(constraint_ok(ins) for ins in by_pos[pos]):
                dfs(pos + 1)
            assigned[pos] = None

    dfs(0)
    if not solutions:
        raise ValueError("no flag recovered")
    if len(solutions) > 1:
        raise ValueError(f"multiple solutions found: {solutions[:2]}")
    return solutions[0]


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
    root = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description="Private VM lifter/solver for chall-4.")
    parser.add_argument("--source", default=str(root / "gen.cpp"), help="path to challenge source with encrypted VM constants")
    parser.add_argument("--check", metavar="FLAG", help="check a candidate with the lifted VM IR")
    parser.add_argument("--dump-ir", action="store_true", help="print decrypted VM IR")
    parser.add_argument("--verify-bin", action="store_true", help="run local dist binaries with the recovered flag")
    parser.add_argument(
        "--charset",
        default="".join(chr(i) for i in range(32, 127)),
        help="candidate charset for MITM recovery",
    )
    args = parser.parse_args()

    program = load_program(args.source)
    ir = disassemble(program)

    if args.dump_ir:
        for ins in ir:
            print(ins)

    if args.check is not None:
        print("Correct!" if check_ir(ir, args.check) else "Nope")
        return

    flag = recover_flag(ir, args.charset.encode("ascii"))
    print(flag)
    assert check_ir(ir, flag)

    if args.verify_bin:
        for rel in ("dist/chall-4.exe", "dist/chall-4", "chall-4.exe", "chall-4"):
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
