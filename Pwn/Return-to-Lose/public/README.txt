Return-to-Lose (ret2win)
========================

A traveler arrives at a secret checkpoint and is asked for their name.
The interface looks friendly, but the program hides a secret: there's a
function that can read the flag from a file, but it is never called in
the normal execution path.

Your task is to exploit a buffer overflow in the program to overwrite the
return address and make the `win` function run. This is a basic Linux
x86-64 exploitation challenge to get you familiar with how the stack works
and how to redirect execution flow.

Files:

  vuln    Linux x86_64 ELF (needs flag.txt next to it when run)

Connect:

  nc <host> <port>

Or run it locally and feed a payload over stdin:

  ./vuln
  python3 -c 'print("A" * 80)' | ./vuln

Hints:

  1. There's a very interesting function that's never called from main.
  2. You control the return address. `read` reads more than the buffer
     size.
  3. Run `checksec`: is PIE on or off? If it's off, function addresses
     are fixed.

Flag format: LYKNCTF{...}
