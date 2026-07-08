Shop
====

A tiny CLI shop. You start with 1836 coins; the flag ("The Flag") costs
36363636 coins -- clearly out of budget. The cashier charges
price * quantity. Walk out with the flag anyway.

Two builds of the SAME challenge are provided, pick the one for your OS:

  shop        Linux   x86_64 ELF
  shop.exe    Windows x86_64 PE

Usage:

  ./shop

Interact via:

  c    view catalog
  b    buy (asks for item index, then quantity)
  q    quit

The balance is printed after every transaction.

Hints:

  1. The bug isn't a buffer overflow.
  2. Check the data types and the sign of the numbers involved.
  3. A value that's too large can wrap around.

Goal: make the cashier think you have enough money -- by abusing how it
computes the total, not by earning coins "legitimately". Successfully
buying "The Flag" prints the flag.

Flag format: LYKNCTF{...}
