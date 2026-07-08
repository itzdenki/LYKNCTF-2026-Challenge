#!/usr/bin/env python3
"""End-to-end build for the cover-art LSB variant (Thanh Hoa 2).

Run from this directory:  python build_all.py
Requires lyknctf.orig.mp4 (the raw source video) to be present next to this
script; that source asset is not shipped in this archive, only the final
products are (lyknctf.mp4, secret.zip, cover.png, etc.) — this script is
kept for reference/rebuilding, not for re-running as-is.

Produces lyknctf.mp4 = original A/V (untouched, -c copy) + PNG cover art
carrying the password in its LSBs + a trailing AES-256 ZIP holding the flag.
No audio is re-encoded, so there is no spectrogram buzz.
"""
import hashlib
import os
import subprocess
import sys

from PIL import Image

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lsb                    # noqa: E402
import make_cover             # noqa: E402
from make_zip import PASSWORD, FLAG  # noqa: E402

SRC   = "lyknctf.orig.mp4"
BASE  = "base.png"
COVER = "cover.png"
ZIP   = "secret.zip"
MUX   = "muxed.mp4"
OUT   = "lyknctf.mp4"
CHECK = "_check_cover.png"


def run(cmd):
    print("  $", " ".join(cmd))
    subprocess.run(cmd, check=True)


def ffprobe(args):
    return subprocess.run(["ffprobe", "-v", "error", *args],
                          capture_output=True, text=True).stdout.strip()


def main():
    assert os.path.exists(SRC), f"missing source video {SRC}"

    print("[1/6] AES-256 ZIP (flag)")
    run([sys.executable, "make_zip.py"])

    print("[2/6] grab a base frame for the cover")
    run(["ffmpeg", "-y", "-v", "error", "-ss", "12", "-i", SRC,
         "-frames:v", "1", BASE])

    print("[3/6] build cover PNG + LSB-embed password")
    make_cover.main()

    print("[4/6] mux cover as attached_pic (video+audio copied, no re-encode)")
    run(["ffmpeg", "-y", "-v", "error", "-i", SRC, "-i", COVER,
         "-map", "0", "-map", "1", "-c", "copy",
         "-disposition:v:1", "attached_pic", MUX])

    print("[5/6] append trailing AES ZIP")
    with open(OUT, "wb") as o:
        o.write(open(MUX, "rb").read())
        o.write(open(ZIP, "rb").read())

    print("[6/6] verify")
    ok = True

    # a) cover round-trips out of the FINAL file with the password intact
    subprocess.run(["ffmpeg", "-y", "-v", "error", "-i", OUT,
                    "-map", "0:v:1", "-c", "copy", CHECK], check=True)
    back = lsb.extract(Image.open(CHECK), 64)
    r = PASSWORD in back
    print(f"    [{'OK' if r else 'FAIL'}] cover LSB password recovered: {back.split(b'  ')[0][:40]!r}")
    ok &= r

    # b) attached_pic present, A/V codecs unchanged
    codecs = ffprobe(["-show_entries", "stream=codec_name,codec_type",
                      "-of", "csv=p=0", OUT])
    has_pic = ffprobe(["-select_streams", "v", "-show_entries",
                       "stream_disposition=attached_pic", "-of", "csv=p=0", OUT])
    r = ("h264" in codecs and "aac" in codecs and "png" in codecs
         and "1" in has_pic.split("\n"))
    print(f"    [{'OK' if r else 'FAIL'}] streams: {codecs.split(chr(10))} attached_pic={has_pic.split(chr(10))}")
    ok &= r

    # c) audio bytes identical to source (proves no re-encode / no buzz)
    def audio_md5(path):
        out = subprocess.run(["ffmpeg", "-v", "error", "-i", path,
                              "-map", "0:a", "-c", "copy", "-f", "md5", "-"],
                             capture_output=True, text=True).stdout.strip()
        return out
    r = audio_md5(SRC) == audio_md5(OUT) != ""
    print(f"    [{'OK' if r else 'FAIL'}] audio identical to source (no re-encode)")
    ok &= r

    # d) still decodes / plays
    p = subprocess.run(["ffmpeg", "-v", "error", "-i", OUT, "-t", "3",
                        "-f", "null", "-"], capture_output=True, text=True)
    r = p.returncode == 0 and p.stderr.strip() == ""
    print(f"    [{'OK' if r else 'FAIL'}] decodes 3s without error")
    ok &= r

    # e) trailing ZIP opens with the password and holds the right flag
    import pyzipper
    with pyzipper.AESZipFile(OUT) as zf:
        zf.setpassword(PASSWORD)
        got = zf.read("flag.txt").decode().strip()
    r = got == FLAG
    print(f"    [{'OK' if r else 'FAIL'}] trailing AES ZIP -> flag.txt == FLAG")
    ok &= r

    sha = hashlib.sha256(open(OUT, "rb").read()).hexdigest()
    size = os.path.getsize(OUT)
    print(f"\n  {OUT}  ({size:,} bytes)")
    print(f"  sha256 = {sha}")

    # solve illustration
    Image.open(CHECK).save("SOLVE_cover.png")
    os.remove(CHECK)

    print("\nALL CHECKS PASSED — ship lyknctf.mp4" if ok
          else "\n*** SOME CHECKS FAILED ***")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
