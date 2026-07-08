import random
from pathlib import Path


SEED = 0x1337
FLAG_PATH = Path("flag.txt")
OUTPUT_PATH = Path("output.txt")

TOKENS = {
    "+": "waguri_kaoruko",
    "-": "tsumugi_rintaro",
    ">": "usami_shohei",
    "<": "natsusawa_saku",
    "[": "yorita_ayato",
    "]": "hoshina_subaru",
    ",": "kaoru_hana",
    ".": "madoka_yuzuhara",
}


def temp_noise(rng, min_offset=3, max_offset=8):
    """Use far scratch cells, clear them, then return to the original pointer."""
    offset = rng.randint(min_offset, max_offset)
    body = rng.choice(
        [
            "+[-]",
            "++[--]",
            "+++[-]",
            "[-]+[-]",
            ">+[-]<",
            ">++[--]<",
        ]
    )
    return ">" * offset + body + "<" * offset


def noisy_repeat(ch, count, rng):
    chunks = []
    remaining = count

    while remaining:
        take = rng.randint(1, min(remaining, 11))
        chunks.append(ch * take)
        remaining -= take

        if remaining and rng.random() < 0.65:
            chunks.append(temp_noise(rng))

    return "".join(chunks)


def is_prime(value):
    if value < 2:
        return False

    for factor in range(2, int(value**0.5) + 1):
        if value % factor == 0:
            return False

    return True


def divisors(value):
    return [factor for factor in range(1, value + 1) if value % factor == 0]


def factors_for(value):
    factors = [factor for factor in divisors(value) if 1 < factor < value]
    if not factors:
        return 1, value

    left = factors[len(factors) // 2]
    return left, value // left


def split_offset(value, rng):
    parts = []
    remaining = value

    while remaining:
        if remaining <= 12:
            parts.append(remaining)
            break

        part = rng.randint(6, min(remaining, 28))
        while is_prime(part) and part > 8:
            part -= 1
        parts.append(part)
        remaining -= part

    rng.shuffle(parts)
    return parts


def add_product_to_cell1(value, rng):
    fac1, fac2 = factors_for(value)

    # From cell0: build fac1 in cell2, multiply it into cell1, return to cell0.
    return "".join(
        [
            ">>",
            noisy_repeat("+", fac1, rng),
            temp_noise(rng, min_offset=2, max_offset=6),
            "[<",
            noisy_repeat("+", fac2, rng),
            ">-]",
            temp_noise(rng, min_offset=2, max_offset=6),
            "<<",
        ]
    )


def add_direct_to_cell1(value, rng):
    # From cell0: add a small tail directly into cell1, return to cell0.
    return ">" + noisy_repeat("+", value, rng) + "<"


def add_offset_to_cell1(offset, rng):
    code = []

    for part in split_offset(offset, rng):
        if part >= 8 and not is_prime(part):
            code.append(add_product_to_cell1(part, rng))
        else:
            code.append(add_direct_to_cell1(part, rng))

        if rng.random() < 0.8:
            code.append(temp_noise(rng))

    return "".join(code)


def fail_trap(rng):
    return rng.choice(
        [
            "[><]",
            "[>+[-]<]",
            "[>>+[-]<<]",
            "[>>>++[--]<<<]",
        ]
    )


def check_char(char, rng):
    offset = rng.randint(30, 70)
    while is_prime(offset):
        offset = rng.randint(30, 70)

    rhs = ord(char) + offset

    return "".join(
        [
            temp_noise(rng),
            ",",
            temp_noise(rng),
            add_offset_to_cell1(offset, rng),
            ">[-<+>]<",
            temp_noise(rng),
            noisy_repeat("-", rhs, rng),
            fail_trap(rng),
        ]
    )


def encode_esolang(brainfuck):
    return " ".join(TOKENS[instruction] for instruction in brainfuck)


def decode_esolang(source):
    reverse = {value: key for key, value in TOKENS.items()}
    return "".join(reverse[token] for token in source.split())


def main():
    rng = random.Random(SEED)
    flag = FLAG_PATH.read_text().strip()

    brainfuck = "".join(check_char(char, rng) for char in flag)
    esolang = encode_esolang(brainfuck)

    assert decode_esolang(esolang) == brainfuck
    OUTPUT_PATH.write_text(esolang)

    print(f"wrote {OUTPUT_PATH} ({len(esolang.split())} tokens)")


if __name__ == "__main__":
    main()
