#!/usr/bin/env python3
"""Layer 2: build the cover-art PNG and hide the ZIP password in its LSBs.

Base image = a real frame grabbed from the source video (looks like a natural
poster/thumbnail, so the stego is less obvious). Falls back to a generated
gradient if the frame is missing. The password is LSB-embedded (see lsb.py) and
the result is verified by re-extracting before the PNG is written.
"""
import os
from PIL import Image, ImageDraw
import lsb

PASSWORD = b"NEMCHUATHANHHOA"
SEP      = b" "                 # separator so repeats stay readable in zsteg
BASE     = "base.png"    # frame grabbed by build_all.py (optional)
OUT      = "cover.png"


def make_base():
    if os.path.exists(BASE):
        return Image.open(BASE).convert("RGB")
    # fallback: dark vertical gradient, 1280x720
    w, h = 1280, 720
    img = Image.new("RGB", (w, h))
    px = img.load()
    for y in range(h):
        c = int(20 + 60 * y / h)
        for x in range(w):
            px[x, y] = (c, c // 2, c // 3)
    ImageDraw.Draw(img).text((40, 40), "LYKNCTF", fill=(200, 200, 200))
    return img


def main():
    base = make_base()
    stego = lsb.embed(base, PASSWORD + SEP)
    stego.save(OUT)                                   # PNG = lossless -> LSB kept

    # verify round-trip on the saved file
    back = lsb.extract(Image.open(OUT), 64)
    assert PASSWORD in back, f"self-check failed: {back!r}"
    print(f"wrote {OUT} ({base.size[0]}x{base.size[1]}), "
          f"embedded+verified password={PASSWORD.decode()}")


if __name__ == "__main__":
    main()
