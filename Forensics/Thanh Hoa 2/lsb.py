#!/usr/bin/env python3
"""LSB stego helpers for the cover-art layer.

Scheme (zsteg-compatible: b1,rgb,msb,xy):
  - walk pixels row-major (x fastest, then y)  -> "xy"
  - per pixel take LSB of R, then G, then B    -> "rgb", "b1"
  - assemble bytes most-significant-bit first   -> "msb"
The message is repeated to fill the whole LSB plane, so a `zsteg -a` string
scan surfaces a long, obviously-readable run.
"""
import numpy as np
from PIL import Image


def _bits_msb_first(data: bytes):
    for byte in data:
        for i in range(7, -1, -1):
            yield (byte >> i) & 1


def embed(base_img: "Image.Image", message: bytes) -> "Image.Image":
    """Fill every RGB LSB (row-major, MSB-first) with `message` repeated."""
    img = base_img.convert("RGB")
    arr = np.array(img, dtype=np.uint8)          # (H, W, 3)
    flat = arr.reshape(-1)                        # R,G,B,R,G,B... row-major
    cap = flat.size                              # one bit per channel-sample
    reps = cap // (len(message) * 8) + 1
    stream = message * reps
    bits = np.fromiter(_bits_msb_first(stream), dtype=np.uint8, count=cap)
    flat = (flat & 0xFE) | bits
    return Image.fromarray(flat.reshape(arr.shape), "RGB")


def extract(img: "Image.Image", nbytes: int) -> bytes:
    """Read the first `nbytes` bytes out of the RGB LSBs (MSB-first)."""
    flat = np.array(img.convert("RGB"), dtype=np.uint8).reshape(-1)
    bits = (flat[: nbytes * 8] & 1).astype(np.uint8)
    packed = np.packbits(bits)                   # MSB-first packing
    return packed.tobytes()
