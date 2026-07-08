#!/usr/bin/env python3
"""Layer 1: create an AES-256 encrypted ZIP containing the flag (build2 variant)."""
import pyzipper

FLAG = "LYKNCTF{N3M_CHU4_TH4NH_H04_D4C_S4N_XU_TH4NH}"
PASSWORD = b"NEMCHUATHANHHOA"      # <-- also hidden via LSB in the MP4 cover art
OUT = "secret.zip"


def main():
    with pyzipper.AESZipFile(OUT, "w",
                             compression=pyzipper.ZIP_DEFLATED,
                             encryption=pyzipper.WZ_AES) as zf:
        zf.setpassword(PASSWORD)
        zf.setencryption(pyzipper.WZ_AES, nbits=256)
        zf.writestr("flag.txt", FLAG + "\n")
    print(f"wrote {OUT} (AES-256), password={PASSWORD.decode()}, flag len={len(FLAG)}")


if __name__ == "__main__":
    main()
