# Writeup - Thanh Hoa 2

## Challenge Info

- Category: Forensics
- Topic: Trailing ZIP (AES), MP4 cover-art LSB steganography
- Difficulty: Medium / medium-hard
- Flag format: `LYKNCTF{...}`
- File given to players: `lyknctf.mp4` *(only this file — everything else
  in this folder leaks the answer)*

A variant of the **Thanh Hoa 1** challenge — the audible spectrogram
"buzz" is removed entirely. Video and audio keep the original encode
(`-c copy`, no re-encoding); the password is hidden in the MP4's
**cover-art** instead.

## How the Challenge Is Built (2 Layers)

1. **Trailing AES ZIP.** Same as Thanh Hoa 1: an **AES-256** encrypted ZIP
   containing `flag.txt` is appended to the **end** of the MP4. The video
   still plays normally; the ZIP sits in the tail, so carving
   (`binwalk`/`unzip -l`) finds it (reports "extra bytes at beginning").
2. **Password in the cover-art (LSB stego).** A PNG (one frame grabbed
   from the source video, so it looks like a normal thumbnail) is
   embedded as the MP4's **cover-art / `attached_pic`** stream. The
   password `NEMCHUATHANHHOA` is written into the **LSB of the RGB
   channels** (row-major, MSB-first — matches `zsteg b1,rgb,msb,xy`),
   repeated across the whole image for easy reading. PNG is lossless so
   the LSBs survive; the audio/video streams are never touched, so there
   is no spectrogram buzz.

## Intended Solve Path

1. `binwalk lyknctf.mp4` / `unzip -l lyknctf.mp4` → a **Zip archive** is
   visible at the end; `flag.txt` inside.
2. Extract it → AES (`unzip` reports *unsupported compression method
   99*). Can't be cracked with bkcrack (AES, not ZipCrypto) → the
   password has to be **found**.
3. `ffprobe lyknctf.mp4` → reveals a **second video stream tagged
   `attached_pic` (cover art)** — the key step, not obvious if you only
   open the file in a video player.
4. Extract the cover:
   - `ffmpeg -i lyknctf.mp4 -map 0:v:1 -update 1 -frames:v 1 cover.png`
   - or `exiftool -Picture -b lyknctf.mp4 > cover.png`
5. Inspect the LSBs: `zsteg -a cover.png` (or StegSolve / a Python script)
   → reads `NEMCHUATHANHHOA` (config `b1,rgb,msb,xy`, an obviously
   repeating string).
6. Extract with a tool that supports AES ZIPs: `7z x lyknctf.mp4
   -pNEMCHUATHANHHOA` → `flag.txt` → flag.

## Tools Players Need

- Trailing data: `binwalk` / `foremost` / a hex editor / `unzip -l`.
- Detecting and extracting cover-art: `ffprobe` + `ffmpeg` / `exiftool` /
  `mp4box`.
- Reading LSB PNG stego: **zsteg** / **StegSolve** / a Python script.
- Opening an AES ZIP: **7-Zip / WinRAR / p7zip** (info-zip's `unzip`
  cannot open AES — intentional, it blocks the bkcrack shortcut).

## Verified

Confirmed directly against the shipped `lyknctf.mp4`:

```bash
ffprobe -v error -show_entries stream=index,codec_name,codec_type -of csv=p=0 lyknctf.mp4
# 0,h264,video
# 1,aac,audio
# 2,png,video   <- the cover-art / attached_pic stream

ffmpeg -y -v error -i lyknctf.mp4 -map 0:v:1 -update 1 -frames:v 1 extracted_cover.png
```

```python
import sys; sys.path.insert(0, ".")
import lsb
from PIL import Image
print(lsb.extract(Image.open("extracted_cover.png"), 64))
# b'NEMCHUATHANHHOA NEMCHUATHANHHOA NEMCHUATHANHHOA NEMCHUATHANHHOA '
```

```python
import pyzipper, io
data = open("lyknctf.mp4", "rb").read()
zip_bytes = data[data.find(b"PK\x03\x04"):]
with pyzipper.AESZipFile(io.BytesIO(zip_bytes)) as zf:
    zf.setpassword(b"NEMCHUATHANHHOA")
    print(zf.read("flag.txt"))
# b'LYKNCTF{N3M_CHU4_TH4NH_H04_D4C_S4N_XU_TH4NH}\n'
```

## Rebuilding

`build_all.py` runs the full pipeline **from this directory**:

```bash
python build_all.py
```

Pipeline: `make_zip.py` (AES ZIP) → grab one frame as the cover base →
`make_cover.py` (LSB-embed + self-verify) → mux the cover as
`attached_pic` (`-c copy`) → append the ZIP → **self-verify** (cover
round-trips, audio md5 matches the source, decodes OK, ZIP opens to the
right flag) → print the sha256.

`build_all.py` needs `lyknctf.orig.mp4` (the raw source video) next to it
— that source asset isn't included in this archive, only the final
products are (`lyknctf.mp4`, `secret.zip`, `cover.png`, etc.), so the
script is kept for reference rather than being directly re-runnable here.

To change the flag/password: edit the constants at the top of
`make_zip.py` and `make_cover.py` (`PASSWORD` must match in both), then
rebuild.

## Files in This Folder

- `lyknctf.mp4` — the **file given to players** (the only one that should
  ever be shared).
- `lsb.py`, `make_zip.py`, `make_cover.py`, `build_all.py` — build
  scripts.
- `cover.png`, `SOLVE_cover.png` — the cover image (password in its LSBs)
  → keep private.
- `base.png`, `muxed.mp4`, `secret.zip` — intermediate build artifacts.

## Solution Illustration

`SOLVE_cover.png` — the cover extracted from the challenge file; running
`zsteg -a` on it reveals the password.

## Flag

```text
LYKNCTF{N3M_CHU4_TH4NH_H04_D4C_S4N_XU_TH4NH}
```
