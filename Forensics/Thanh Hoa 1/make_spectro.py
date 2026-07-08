#!/usr/bin/env python3
"""Layer 2: synthesize audio whose spectrogram spells out the ZIP password.

Technique: render text -> binary image; for each image row (a frequency in the
6-12 kHz band) emit a continuous-phase sine whose amplitude envelope follows the
image brightness along time. Summing the rows "paints" the text into the STFT
magnitude. One instance is tiled across the whole track so a full-file
spectrogram shows the text repeatedly and clearly.
"""
import numpy as np
from PIL import Image, ImageDraw, ImageFont
import wave, os, sys

# ---- tunables -------------------------------------------------------------
TEXT          = "RAUMAPHATAU"
SR            = 44100
F_LOW         = 6400        # Hz  bottom of the drawing band (inside the notch)
F_HIGH        = 11600       # Hz  top of the drawing band (inside the notch)
INSTANCE_SEC  = 34.0        # seconds for one full rendering of the text
TOTAL_SEC     = 386.90      # cover the whole original audio
PEAK          = 0.30        # peak amplitude of the spectro layer (0..1)
FONT_SIZE     = 120
MARGIN_COLS   = 14          # black padding cols each side -> silence at tile seams
OUT_WAV       = "spectro.wav"
OUT_PNG       = "spectro_preview.png"   # rendered text image (debug)
# ---------------------------------------------------------------------------

def load_font(size):
    for p in ("C:/Windows/Fonts/arialbd.ttf", "C:/Windows/Fonts/arial.ttf",
              "arialbd.ttf", "DejaVuSans-Bold.ttf"):
        try:
            return ImageFont.truetype(p, size)
        except OSError:
            continue
    return ImageFont.load_default()

# --- render text to a tight binary image -----------------------------------
font = load_font(FONT_SIZE)
tmp = Image.new("L", (10, 10), 0)
l, t, r, b = ImageDraw.Draw(tmp).textbbox((0, 0), TEXT, font=font)
tw, th = r - l, b - t
img = Image.new("L", (tw + 2 * MARGIN_COLS, th), 0)
ImageDraw.Draw(img).text((MARGIN_COLS - l, -t), TEXT, fill=255, font=font)
arr = (np.asarray(img, dtype=np.float32) / 255.0)   # (H, W), row0 = top
img.save(OUT_PNG)
H, W = arr.shape
print(f"text image: {W}x{H}px  ('{TEXT}')")

# --- synthesize ONE instance ------------------------------------------------
n_inst = int(round(INSTANCE_SEC * SR))
t_samples = np.arange(n_inst) / SR
col_time = (np.arange(W) + 0.5) * (INSTANCE_SEC / W)   # center time of each col
row_freq = F_HIGH - (np.arange(H) / max(H - 1, 1)) * (F_HIGH - F_LOW)  # row0->F_HIGH

inst = np.zeros(n_inst, dtype=np.float32)
for row in range(H):
    env = np.interp(t_samples, col_time, arr[row]).astype(np.float32)  # smooth ramps
    if env.max() < 1e-4:
        continue
    inst += env * np.sin(2 * np.pi * row_freq[row] * t_samples).astype(np.float32)

# normalize one instance, then tile to full length
inst *= PEAK / (np.abs(inst).max() + 1e-9)
reps = int(np.ceil(TOTAL_SEC * SR / n_inst))
full = np.tile(inst, reps)[: int(round(TOTAL_SEC * SR))]

# --- write 16-bit PCM WAV ---------------------------------------------------
pcm = np.clip(full, -1, 1)
pcm16 = (pcm * 32767.0).astype("<i2")
with wave.open(OUT_WAV, "wb") as w:
    w.setnchannels(1)
    w.setsampwidth(2)
    w.setframerate(SR)
    w.writeframes(pcm16.tobytes())

print(f"wrote {OUT_WAV}: {len(full)/SR:.1f}s, {reps} repeats of {INSTANCE_SEC}s, "
      f"band {F_LOW}-{F_HIGH}Hz, peak {PEAK}")
