#include <cstdio>
#include <cstring>

static const int LEN = 33;

static const unsigned char key1[] = {
    0x52, 0x64, 0x71, 0x51, 0x54, 0x76, 0x2d, 0x39
};

static const unsigned char key2[] = {
    0x17, 0x8b, 0x23, 0x42, 0xc1, 0x5e, 0x09, 0xa7
};

static const int perm[LEN] = {
    3, 10, 17, 24, 31, 5, 12, 19, 26, 0, 7,
    14, 21, 28, 2, 9, 16, 23, 30, 4, 11, 18,
    25, 32, 6, 13, 20, 27, 1, 8, 15, 22, 29
};

static const unsigned char target[LEN] = {
    0x66, 0x15, 0xe4, 0x34, 0x0c, 0x1b, 0x3e, 0xd3,
    0x22, 0xd1, 0xea, 0x25, 0x86, 0x12, 0x88, 0x6f,
    0xae, 0x57, 0x72, 0x18, 0xc9, 0xdb, 0x10, 0x36,
    0x3e, 0x0b, 0x48, 0x07, 0x44, 0xf9, 0x01, 0xff,
    0x07
};

static unsigned char rol(unsigned char x, int r)
{
    return (unsigned char)((x << r) | (x >> (8 - r)));
}

static void transform(unsigned char buf[LEN])
{
    unsigned char tmp[LEN];

    for (int round = 0; round < 3; round++) {
        for (int i = 0; i < LEN; i++) {
            unsigned char x = buf[i];
            x ^= key1[(i + round * 3) % sizeof(key1)];
            x = rol(x, ((i + round) % 7) + 1);
            x = (unsigned char)(
                x + key2[(i * 5 + round) % sizeof(key2)] +
                ((i * 13 + round * 29) & 0xff)
            );
            buf[i] = x;
        }

        for (int i = 0; i < LEN; i++) {
            tmp[perm[i]] = buf[i];
        }

        unsigned char acc = (unsigned char)(0x5a + round * 0x31);
        for (int i = 0; i < LEN; i++) {
            unsigned char x = (unsigned char)(tmp[i] ^ acc ^ ((i * 7 + round) & 0xff));
            buf[i] = x;
            acc = x;
        }
    }
}

int main(int argc, char **argv)
{
    char input[128];

    if (argc > 1) {
        std::strncpy(input, argv[1], sizeof(input) - 1);
        input[sizeof(input) - 1] = '\0';
    } else {
        std::printf("flag: ");
        if (std::fgets(input, sizeof(input), stdin) == NULL) {
            return 1;
        }
        input[std::strcspn(input, "\r\n")] = '\0';
    }

    if (std::strlen(input) != LEN) {
        std::puts("Nope");
        return 1;
    }

    unsigned char buf[LEN];
    std::memcpy(buf, input, LEN);
    transform(buf);

    unsigned char diff = 0;
    for (int i = 0; i < LEN; i++) {
        diff |= (unsigned char)(buf[i] ^ target[i]);
    }

    std::puts(diff == 0 ? "Correct!" : "Nope");
    return diff == 0 ? 0 : 1;
}
