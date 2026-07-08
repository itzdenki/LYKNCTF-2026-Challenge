# Control Freak 1

## Challenge Info

The release contains 2 binaries:

- `chall-2`: Linux x86_64 ELF
- `chall-2.exe`: Windows x86_64 PE

The program is a flag checker. When run, it takes the flag via argv or stdin:

```bash
./chall-2
flag:
```

If the input is correct, it prints:

```text
Correct!
```

If wrong, it prints:

```text
Nope
```

## Recon

Running `strings` shows no plaintext flag, only interface strings like `flag:`, `Correct!`, `Nope`. So the flag isn't stored directly in the binary.

Opening it in Ghidra/IDA, the main flow of `main` is fairly clear:

1. Read input from argv or stdin.
2. Check `strlen(input) == 33`.
3. Copy input into a 33-byte buffer.
4. Call `transform(buf)`.
5. XOR each byte of `buf` with the `target` array.
6. If all bytes match, the input is correct.

Pseudo-code of the check:

```c
if (strlen(input) != 33) {
    puts("Nope");
    return 1;
}

memcpy(buf, input, 33);
transform(buf);

diff = 0;
for (i = 0; i < 33; i++) {
    diff |= buf[i] ^ target[i];
}

puts(diff == 0 ? "Correct!" : "Nope");
```

This tells us the task is to invert `transform(target)` to recover the original input.

## Constants

From the decompiler or a `.rodata` dump, we get the following arrays:

```python
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
```

## Analyzing `transform`

The `transform` function runs 3 rounds. Each round has 3 layers:

1. Mix each byte via XOR, rotate-left, add modulo 256.
2. Permute positions using the `perm` array.
3. Feedback XOR, where each byte depends on the previous output byte.

Rewriting one round's logic in Python:

```python
for i in range(33):
    x = buf[i]
    x ^= key1[(i + rnd * 3) % 8]
    x = rol(x, ((i + rnd) % 7) + 1)
    x = (
        x
        + key2[(i * 5 + rnd) % 8]
        + ((i * 13 + rnd * 29) & 0xff)
    ) & 0xff
    mixed[i] = x

for i in range(33):
    tmp[perm[i]] = mixed[i]

acc = (0x5a + rnd * 0x31) & 0xff
for i in range(33):
    out[i] = tmp[i] ^ acc ^ ((i * 7 + rnd) & 0xff)
    acc = out[i]
```

Every transformation is invertible:

- XOR is its own inverse.
- Rotate-left is inverted by rotate-right.
- Addition modulo 256 is inverted by subtraction modulo 256.
- The permutation is invertible since `perm` is a permutation covering all 33 positions.
- The feedback XOR is invertible because when reversing a round, we already have the full `out` array, so `acc` at position `i > 0` is exactly `out[i - 1]`.

## Reversing the Feedback

In encryption:

```python
out[i] = tmp[i] ^ acc ^ salt
```

where:

```python
salt = (i * 7 + rnd) & 0xff
acc = (0x5a + rnd * 0x31) & 0xff  # if i == 0
acc = out[i - 1]                  # if i > 0
```

Since XOR is self-inverse:

```python
tmp[i] = out[i] ^ acc ^ salt
```

Code:

```python
tmp = [0] * LEN
for i in range(LEN):
    acc = (0x5a + rnd * 0x31) & 0xff if i == 0 else buf[i - 1]
    tmp[i] = buf[i] ^ acc ^ ((i * 7 + rnd) & 0xff)
```

Here `buf` is the output of the current round.

## Reversing the Permutation

In encryption:

```python
tmp[perm[i]] = mixed[i]
```

To recover `mixed[i]`, simply read it back:

```python
mixed[i] = tmp[perm[i]]
```

Code:

```python
mixed = [0] * LEN
for i in range(LEN):
    mixed[i] = tmp[perm[i]]
```

No need to build a separate inverse permutation — the formula above already correctly inverts the original assignment.

## Reversing the Byte Mix

In encryption, for each byte:

```python
x ^= key1[(i + rnd * 3) % 8]
x = rol(x, ((i + rnd) % 7) + 1)
x = x + key2[(i * 5 + rnd) % 8] + ((i * 13 + rnd * 29) & 0xff)
```

We reverse it in the opposite order:

1. Subtract the added part.
2. Rotate-right to invert rotate-left.
3. XOR back with `key1`.

Code:

```python
x = (
    x
    - key2[(i * 5 + rnd) % len(key2)]
    - ((i * 13 + rnd * 29) & 0xff)
) & 0xff
x = ror(x, ((i + rnd) % 7) + 1)
x ^= key1[(i + rnd * 3) % len(key1)]
```

Since encryption runs rounds `0 -> 1 -> 2`, decryption must run them in reverse: `2 -> 1 -> 0`.

## Solver

Full solver script:

```python
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

print(bytes(buf).decode())
```

Run the solver:

```bash
python solve.py
```

Output:

```text
LYKNCTF{H0W_D1D_Y0U_C0NTR0L_TH4T}
```

## Verify

Verify against the Linux binary:

```bash
./chall-2 'LYKNCTF{H0W_D1D_Y0U_C0NTR0L_TH4T}'
```

Result:

```text
Correct!
```

Verify with a wrong input:

```bash
./chall-2 'LYKNCTF{H0W_D1D_Y0U_C0NTR0L_TH4X}'
```

Result:

```text
Nope
```

## Flag

```text
LYKNCTF{H0W_D1D_Y0U_C0NTR0L_TH4T}
```
