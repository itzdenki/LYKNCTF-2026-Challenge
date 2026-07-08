#!/usr/bin/env python3
"""Layer 1: create an AES-256 encrypted ZIP containing the flag."""
import pyzipper

FLAG = "LYKNCTF{NGU01_TH4NH_H04_4N_R4U_M4_PH4_DU0NG_T4U}"
PASSWORD = b"RAUMAPHATAU"          # <-- also drawn into the audio spectrogram
OUT = "secret.zip"

with pyzipper.AESZipFile(OUT, "w",
                         compression=pyzipper.ZIP_DEFLATED,
                         encryption=pyzipper.WZ_AES) as zf:
    zf.setpassword(PASSWORD)
    zf.setencryption(pyzipper.WZ_AES, nbits=256)
    zf.writestr("flag.txt", FLAG + "\n")

print(f"wrote {OUT} (AES-256), password={PASSWORD.decode()}, flag len={len(FLAG)}")
