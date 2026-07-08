# Writeup - Shop

## Challenge Info

- Category: Pwn
- Topic: Signed integer overflow, no bounds/sign checking
- Flag format: `LYKNCTF{...}`

The release contains 2 binaries plus the readable source:

- `dist/shop`: Linux x86_64 ELF
- `dist/shop.exe`: Windows x86_64 PE
- `shop.c`: full source (shipped readable — the bug is meant to be found by reading it)

A tiny CLI shop. You start with **1836 coins**; the flag ("The Flag") costs
**36363636 coins** — clearly out of budget. The cashier charges
`price * quantity`. Walk out with the flag anyway.

```bash
make            # builds dist/shop (and dist/shop.exe on Windows/MSYS)
./dist/shop
```

Interact via `c` (catalog), `b` (buy), `q` (quit). Buying asks for an
**item index** then a **quantity**; the balance is printed after every
transaction.

## The Bug

`buy()` in `shop.c` computes the cost as a **signed 32-bit** product and
never validates it:

```c
int total = catalog[idx].price * qty;   /* price, qty, total all `int` */
if (total > balance) { ... reject ... }
balance -= total;
```

Two distinct flaws here, each enough to win on its own:

1. **Signed overflow.** `price * qty` can wrap around `2**32`. With
   `price = 36363636`, a large enough `qty` makes the product wrap to a
   small — or deeply negative — 32-bit value that passes the
   `total > balance` check.
2. **No sign check on `qty`.** A *negative* quantity makes `total`
   negative, so `balance -= total` **adds** coins. You can mint unlimited
   money and then buy the flag at full price.

The binary is built with `-fwrapv` so the overflow is well-defined two's
complement wraparound (stable across compilers for this exercise).

## Path A — Overflow a Single Flag Purchase

We want `36363636 * qty`, reduced mod `2**32` and read back as a signed
`int`, to land at some value `<= 1836` (the current balance), with `qty` a
*positive* signed int (the flag guard requires `qty >= 1`).

Unlike an odd price, `36363636` is **even** (`= 4 * 9090909`), so it has no
modular inverse mod `2**32` — we can't solve directly for an exact target.
Instead we scan `qty = 1, 2, 3, ...` and keep the first one whose wrapped
signed total is affordable. Any *negative* wrapped total also qualifies
(it's `<= balance` and, as a bonus, mints coins on top). The scan finds:

```
qty = 60   ->   36363636 * 60  ≡  -2113149136  (mod 2**32, signed)
```

`-2113149136 <= 1836`, so the purchase is accepted; `qty >= 1` holds, so
the flag guard passes; and since the total is negative, `balance` actually
*increases* by over 2 billion coins as a side effect. One purchase, flag
printed:

```
b          # buy
3          # item index = The Flag
60         # quantity
q
```

## Path B — Negative Quantity Mints Coins

Buy the 18-coin Sticker with a negative quantity to inflate the balance
past `36363636`, then buy the flag normally:

```
total = 18 * (-2020101) = -36361818
balance -= total   ->   1836 - (-36361818) = 36363654
```

`36363654 >= 36363636`, so the flag purchase at `qty = 1` succeeds
normally:

```
b
0            # Sticker
-2020101     # negative quantity -> balance jumps to 36,363,654
b
3            # The Flag
1
q
```

## Solver

`solve.py` runs both paths against the real binary (auto-detects
`dist/shop.exe` or `dist/shop`):

```bash
python solve.py
```

Output:

```text
[Path A] quantity = 60  ->  signed total = -2113149136 coin (<= 1836, qty >= 1)
  -> Path A (overflow): GOT FLAG LYKNCTF{wr4p_wr4p_wr4p}

[Path B] buy Sticker qty = -2020101  ->  total = -36361818 coin, new balance = 36363654
  -> Path B (negative qty): GOT FLAG LYKNCTF{wr4p_wr4p_wr4p}
```

## Fix

Use an unsigned wide type and bounds-check, or reject non-positive
quantities:

```c
if (qty <= 0) { puts("Quantity must be positive."); return; }
long long total = (long long)catalog[idx].price * qty;
if (total < 0 || total > balance) { puts("Nope."); return; }
```

Better still: validate at the input boundary and do money math in a type
that cannot silently wrap (or check `__builtin_mul_overflow`).

## Flag

```text
LYKNCTF{wr4p_wr4p_wr4p}
```
