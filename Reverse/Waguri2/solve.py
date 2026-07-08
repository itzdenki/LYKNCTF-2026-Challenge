from pathlib import Path


OUTPUT_PATH = Path("output.txt")

TOKENS = {
    "waguri_kaoruko": "+",
    "tsumugi_rintaro": "-",
    "usami_shohei": ">",
    "natsusawa_saku": "<",
    "yorita_ayato": "[",
    "hoshina_subaru": "]",
    "kaoru_hana": ",",
    "madoka_yuzuhara": ".",
}

CANDIDATES = [ord(ch) for ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789{}_!?-"]
CANDIDATES += [value for value in range(32, 127) if value not in CANDIDATES]


def decode_esolang(source):
    try:
        return "".join(TOKENS[token] for token in source.split())
    except KeyError as error:
        raise ValueError(f"unknown token: {error.args[0]}") from error


def build_jump_table(program):
    stack = []
    jump = {}

    for pc, instruction in enumerate(program):
        if instruction == "[":
            stack.append(pc)
        elif instruction == "]":
            if not stack:
                raise ValueError(f"unmatched closing bracket at pc={pc}")
            start = stack.pop()
            jump[start] = pc
            jump[pc] = start

    if stack:
        raise ValueError(f"unmatched opening bracket at pc={stack[-1]}")

    return jump


def compact_tape(tape):
    return tuple(sorted((idx, value) for idx, value in tape.items() if value))


def run_until_next_input(program, jump, state, input_byte, max_steps=100_000):
    pc, ptr, tape = state
    tape = tape.copy()
    used_input = False
    seen = set()
    steps = 0

    while pc < len(program):
        if steps > max_steps:
            return None

        key = (pc, ptr, used_input, compact_tape(tape))
        if key in seen:
            return None
        seen.add(key)

        instruction = program[pc]

        if instruction == "+":
            tape[ptr] = tape.get(ptr, 0) + 1
        elif instruction == "-":
            tape[ptr] = tape.get(ptr, 0) - 1
        elif instruction == ">":
            ptr += 1
        elif instruction == "<":
            ptr -= 1
        elif instruction == ",":
            if used_input:
                return pc, ptr, tape
            tape[ptr] = input_byte
            used_input = True
        elif instruction == "[":
            if tape.get(ptr, 0) == 0:
                pc = jump[pc]
        elif instruction == "]":
            if tape.get(ptr, 0) != 0:
                pc = jump[pc]

        pc += 1
        steps += 1

    return pc, ptr, tape


def solve(program):
    jump = build_jump_table(program)
    state = (0, 0, {})
    flag = []

    while state[0] < len(program):
        for candidate in CANDIDATES:
            next_state = run_until_next_input(program, jump, state, candidate)
            if next_state is not None:
                flag.append(chr(candidate))
                state = next_state
                print("".join(flag))
                break
        else:
            raise RuntimeError(f"cannot recover byte at pc={state[0]}")

    return "".join(flag)


def main():
    source = OUTPUT_PATH.read_text()
    program = decode_esolang(source)
    flag = solve(program)
    print(f"\nflag: {flag}")


if __name__ == "__main__":
    main()
