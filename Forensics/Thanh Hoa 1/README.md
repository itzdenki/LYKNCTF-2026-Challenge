# Writeup - Thanh Hoa 1

## Challenge Info

- Category: Forensics
- Topic: Trailing ZIP (AES), audio spectrogram steganography
- Difficulty: Medium
- Flag format: `LYKNCTF{...}`
- File given to players: `lyknctf.mp4`

## Description

The file given to players is a normal-looking video, `lyknctf.mp4`. It
plays fine in any player. The challenge is built in two layers:

1. **Trailing AES ZIP.** An **AES-256** encrypted ZIP containing
   `flag.txt` is appended to the **end** of the MP4. The video still plays
   normally; the ZIP sits in the tail, so carving tools
   (`binwalk`/`foremost`) or a hex dump find it (`PK` header at offset
   `31910541`).
2. **Password in the spectrogram.** The ZIP password, `RAUMAPHATAU`, is
   "drawn" into the audio's frequency spectrum in the **6.4–11.6 kHz**
   band (the original music was notched out in that band and the text was
   painted in instead, so it reads clearly throughout the whole track).

## Intended Solve Path

1. `binwalk lyknctf.mp4` / inspect the hex → a **Zip archive** is visible
   at the end of the file. (Or `unzip -l lyknctf.mp4` → warns "extra bytes
   at beginning".)
2. Extract it → `flag.txt` is **AES**-encrypted (`unzip` reports
   *unsupported compression method 99*). It can't be cracked with
   known-plaintext/bkcrack (that only works on the legacy ZipCrypto
   cipher, not AES) — the password has to be **found**, not brute-forced.
3. The only remaining clue is the **audio** → extract it and open a
   **spectrogram**:
   - Audacity → *Spectrogram view*, or **Sonic Visualiser**, or:
     `ffmpeg -i lyknctf.mp4 a.wav && ffmpeg -i a.wav -lavfi showspectrumpic=s=1920x800 s.png`
   - `RAUMAPHATAU` is readable in the ~6–12 kHz band, repeating for the
     whole track.
4. Extract with a tool that supports AES ZIPs (**7-Zip / WinRAR / p7zip /
   Python `pyzipper`**): `7z x lyknctf.mp4 -pRAUMAPHATAU` → `flag.txt` →
   flag.

## Tools Players Need

- Detecting trailing data: `binwalk` / `foremost` / a hex editor.
- Reading the spectrogram: **Audacity** / **Sonic Visualiser** / ffmpeg's
  `showspectrumpic`.
- Opening an AES ZIP: **7-Zip / WinRAR / p7zip** (info-zip's `unzip`
  cannot open AES ZIPs — that's intentional, it blocks the bkcrack
  shortcut).

## Verified

Confirmed directly against the shipped `lyknctf.mp4`:

```bash
python -c "
data = open('lyknctf.mp4','rb').read()
print(data.find(b'PK\x03\x04'))   # -> 31910541
"
```

```python
import pyzipper, io
data = open('lyknctf.mp4', 'rb').read()
zip_bytes = data[data.find(b'PK\x03\x04'):]
with pyzipper.AESZipFile(io.BytesIO(zip_bytes)) as zf:
    zf.setpassword(b'RAUMAPHATAU')
    print(zf.read('flag.txt'))
# b'LYKNCTF{NGU01_TH4NH_H04_4N_R4U_M4_PH4_DU0NG_T4U}\n'
```

The spectrogram was also re-rendered directly from the shipped file
(`ffmpeg -i lyknctf.mp4 -t 40 -vn clip.wav && ffmpeg -i clip.wav -lavfi
showspectrumpic=s=1920x800:legend=1 check.png`) and `RAUMAPHATAU` is
clearly legible in the 6–12 kHz band, matching `SOLVE_spectrogram.png`.

## Rebuilding

Scripts in this folder (run from here):

1. `python make_zip.py` → `secret.zip` (AES-256, flag)
2. `python make_spectro.py` → `spectro.wav` (password drawn in 6.4–11.6 kHz)
3. Remux (notch out the band + mix in the text, video copied, audio AAC
   192k) → `muxed.mp4`
4. `cat muxed.mp4 secret.zip > lyknctf.mp4`

Step 3 (the remux) isn't scripted in this folder — it was done once
against the original source video, which isn't included here; only the
resulting `muxed.mp4` is kept.

To change the flag/password: edit the constants at the top of
`make_zip.py` and `make_spectro.py`, then re-run and re-concatenate.

## Solution Illustration

`SOLVE_spectrogram.png` — spectrogram taken from the challenge file,
showing the password clearly.

## Flag

```text
LYKNCTF{NGU01_TH4NH_H04_4N_R4U_M4_PH4_DU0NG_T4U}
```
