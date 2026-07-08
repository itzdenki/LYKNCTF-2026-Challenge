# Writeup - Waguri2

## Challenge Info

- Category: Reverse Engineering
- Topic: Esolang, Brainfuck, obfuscated interpreter
- Flag format: `LYKNCTF{*}`

The release contains a single file:

- `output.txt` — the challenge (a program in a custom esolang)

## Description

`output.txt` is a long sequence of space-separated words such as
`waguri_kaoruko`, `tsumugi_rintaro`, `usami_shohei`, `natsusawa_saku`,
`yorita_ayato`, `hoshina_subaru`, `kaoru_hana`, `madoka_yuzuhara`. This is
just Brainfuck with each of the 8 instructions renamed to a character
name:

| Token | Brainfuck |
|---|---|
| `waguri_kaoruko` | `+` |
| `tsumugi_rintaro` | `-` |
| `usami_shohei` | `>` |
| `natsusawa_saku` | `<` |
| `yorita_ayato` | `[` |
| `hoshina_subaru` | `]` |
| `kaoru_hana` | `,` |
| `madoka_yuzuhara` | `.` |

Decoding the tokens back to Brainfuck gives a program that reads the flag
one character at a time (`,`) and, for each character, runs a large block
of heavily obfuscated code before reading the next one. There is no `.`
(output) anywhere — the program never prints anything, it just accepts or
hangs.

## Recon

`gen.py` is the generator and shows exactly how each character is checked.
For every flag character it emits one `check_char` block:

```python
def check_char(char, rng):
    offset = rng.randint(30, 70)
    while is_prime(offset):
        offset = rng.randint(30, 70)

    rhs = ord(char) + offset

    return "".join([
        temp_noise(rng),
        ",",
        temp_noise(rng),
        add_offset_to_cell1(offset, rng),
        ">[-<+>]<",
        temp_noise(rng),
        noisy_repeat("-", rhs, rng),
        fail_trap(rng),
    ])
```

Tracing the tape pointer through one block:

1. `,` reads one input byte into `cell0`.
2. `add_offset_to_cell1(offset, ...)` builds the value `offset` into
   `cell1`, either by adding it directly (`add_direct_to_cell1`) or, for
   larger composite values, by building a factor in a scratch cell and
   multiplying it into `cell1` (`add_product_to_cell1`). Which path is
   taken, how the offset is split into parts (`split_offset`), and how
   many "wasted" scratch-cell excursions (`temp_noise`) are inserted are
   all randomized — this is pure noise, it doesn't change the result.
3. `>[-<+>]<` moves the pointer to `cell1` and transfers its value into
   `cell0` (`cell0 += cell1; cell1 = 0`), then returns to `cell0`. At this
   point `cell0 = input_byte + offset`.
4. `noisy_repeat("-", rhs, ...)` subtracts `rhs = ord(char) + offset` from
   `cell0` (again split into randomized chunks with scratch-cell noise in
   between). If the input byte was correct, `cell0` is now exactly `0`.
5. `fail_trap(rng)` is a loop guarded by `cell0`, e.g. `[><]`. If
   `cell0 == 0` the loop body never executes and control falls through to
   the next character's block. If `cell0 != 0` (wrong guess), the loop
   spins forever — none of the trap bodies (`[><]`, `[>+[-]<]`, ...) ever
   make `cell0` reach `0`, so the interpreter hangs.

Everything else in `gen.py` (`temp_noise`, `noisy_repeat`, `split_offset`,
`factors_for`, prime-avoidance in `offset`/`split_offset`) exists purely to
make static analysis annoying: random scratch cells, random chunk sizes,
random choice of direct-add vs. multiply. None of it changes the
observable behavior of "correct byte -> continue, wrong byte -> hang
forever".

## Exploitation Idea

Because a wrong character always makes the interpreter loop forever and a
correct character always lets it proceed to the next `,`, the whole
obfuscated wall of Brainfuck can be treated as a black-box oracle: run the
program with a candidate byte, and see whether execution reaches the next
input instruction (or the end of the program) or gets stuck.

To detect "stuck" without literally waiting forever, track visited
interpreter states `(pc, ptr, used_input, tape)` between one input and the
next. Brainfuck with no I/O side effects and a bounded window is
deterministic, so if the exact same state ever repeats, the run is in a
loop and can never reach another `,` — it can be aborted immediately
instead of spinning.

This is exactly what `solve.py` does:

1. Decode the esolang tokens back to raw Brainfuck (`decode_esolang`).
2. Build the bracket jump table once (`build_jump_table`).
3. `run_until_next_input` executes from the current `(pc, ptr, tape)`
   state, feeding in one candidate byte at the first unconsumed `,`, and
   runs until either the *next* `,` is reached (returns the new state) or
   a previously-seen `(pc, ptr, used_input, tape)` combination repeats
   (returns `None`, meaning this candidate is wrong).
4. `solve` tries a small printable-character candidate list per position;
   the one that doesn't get rejected is the correct flag byte. Repeat
   left to right until the whole program has been consumed.

No understanding of the noise generators is required at all — the solver
never looks at `gen.py`'s obfuscation logic, it only needs the observation
that wrong bytes loop forever.

## Solver

```bash
python solve.py
```

Output (abridged):

```text
LYKNCTF{K
LYKNCTF{K4
...
LYKNCTF{K40RU_H4N4_W4_R1N_T0_S4KU}

flag: LYKNCTF{K40RU_H4N4_W4_R1N_T0_S4KU}
```

## Flag

```text
LYKNCTF{K40RU_H4N4_W4_R1N_T0_S4KU}
```
