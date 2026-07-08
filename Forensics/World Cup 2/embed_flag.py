#!/usr/bin/env python3
"""
Embed flag into worldcup2.png using file concatenation and steganography
"""
from PIL import Image
import zipfile
import os

def create_hidden_zip(flag_text, zip_path):
    """Create a ZIP file containing the flag"""
    # Create flag file
    flag_file = 'flag_hidden.txt'
    with open(flag_file, 'w') as f:
        f.write(flag_text)

    # Create ZIP
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.write(flag_file)

    # Clean up
    os.remove(flag_file)
    print(f"[+] Created ZIP archive: {zip_path}")

def concatenate_files(image_path, zip_path, output_path):
    """Concatenate ZIP to end of PNG"""
    with open(image_path, 'rb') as img:
        img_data = img.read()

    with open(zip_path, 'rb') as zp:
        zip_data = zp.read()

    with open(output_path, 'wb') as out:
        out.write(img_data)
        out.write(zip_data)

    print(f"[+] Concatenated ZIP to PNG")

def add_string_markers(image_path, output_path, markers):
    """Add searchable string markers"""
    with open(image_path, 'rb') as f:
        data = f.read()

    # Add markers at the end
    marker_data = b'\x00' * 32  # Padding
    for marker in markers:
        marker_data += marker.encode('utf-8') + b'\x00' * 16

    with open(output_path, 'wb') as f:
        f.write(data)
        f.write(marker_data)

    print(f"[+] Added string markers")

def main():
    flag = "LYKNCTF{RespectToCaboVerde}"

    # Step 1: Create hidden ZIP with flag
    print("[*] Creating hidden ZIP archive...")
    zip_path = 'hidden.zip'
    create_hidden_zip(flag, zip_path)

    # Step 2: Concatenate ZIP to PNG
    print("[*] Concatenating ZIP to PNG...")
    concatenate_files('worldcup2.png', zip_path, 'worldcup2_temp1.png')

    # Step 3: Add string markers for additional hints
    print("[*] Adding string markers...")
    markers = [
        "RESPECT_TO_CABO_VERDE",
        "The warriors fought bravely",
        "Check the file structure"
    ]
    add_string_markers('worldcup2_temp1.png', 'worldcup2_challenge.png', markers)

    # Clean up
    os.remove(zip_path)

    print("\n[+] Challenge image created: worldcup2_challenge.png")
    print(f"[+] Flag embedded: {flag}")
    print("[+] Techniques applied:")
    print("    1. ZIP file concatenated to end of PNG")
    print("    2. String markers for hints")
    print("    3. File structure analysis required")
    print("\n[+] Solution hints:")
    print("    - Use binwalk to detect embedded files")
    print("    - Use strings to find hints")
    print("    - Extract the ZIP archive")

if __name__ == "__main__":
    main()
