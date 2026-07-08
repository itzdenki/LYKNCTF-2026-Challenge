LEN = 33

key1 = [0x52, 0x64, 0x71, 0x51, 0x54, 0x76, 0x2d, 0x39]
key2 = [0x17, 0x8b, 0x23, 0x42, 0xc1, 0x5e, 0x09, 0xa7]

perm = [
    3, 10, 17, 24, 31, 5, 12, 19, 26, 0, 7,
    14, 21, 28, 2, 9, 16, 23, 30, 4, 11, 18,
    25, 32, 6, 13, 20, 27, 1, 8, 15, 22, 29,
]

target = [
    0x66, 0x15, 0xe4, 0x34, 0x0c, 0x1b, 0x3e, 0xd3,
    0x22, 0xd1, 0xea, 0x25, 0x86, 0x12, 0x88, 0x6f,
    0xae, 0x57, 0x72, 0x18, 0xc9, 0xdb, 0x10, 0x36,
    0x3e, 0x0b, 0x48, 0x07, 0x44, 0xf9, 0x01, 0xff,
    0x07,
]


def ror(x, r):
    return ((x >> r) | (x << (8 - r))) & 0xff


def solve():
    buf = target[:]

    for rnd in range(2, -1, -1):
        tmp = [0] * LEN

        for i in range(LEN):
            acc = (0x5a + rnd * 0x31) & 0xff if i == 0 else buf[i - 1]
            tmp[i] = buf[i] ^ acc ^ ((i * 7 + rnd) & 0xff)

        mixed = [0] * LEN
        for i in range(LEN):
            mixed[i] = tmp[perm[i]]

        prev = [0] * LEN
        for i, x in enumerate(mixed):
            x = (
                x
                - key2[(i * 5 + rnd) % len(key2)]
                - ((i * 13 + rnd * 29) & 0xff)
            ) & 0xff
            x = ror(x, ((i + rnd) % 7) + 1)
            x ^= key1[(i + rnd * 3) % len(key1)]
            prev[i] = x

        buf = prev

    return bytes(buf)


if __name__ == "__main__":
    print(solve().decode())
