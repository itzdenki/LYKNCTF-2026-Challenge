#!/usr/bin/env python3
"""
WorldCup1 Challenge Solver
Extracts flag from LSB steganography in PNG image
"""

from PIL import Image

def extract_lsb_red_channel(image_path):
    """Extract hidden message from LSB of red channel"""
    print(f"[*] Opening image: {image_path}")
    img = Image.open(image_path)

    if img.mode != 'RGB':
        img = img.convert('RGB')

    pixels = img.load()
    width, height = img.size
    print(f"[*] Image size: {width}x{height}")

    # Extract LSB from red channel
    binary_data = ""

    print("[*] Extracting LSB data from red channel...")
    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y]
            binary_data += str(r & 1)

            # Check for end marker every 16 bits
            if len(binary_data) >= 16 and len(binary_data) % 16 == 0:
                if binary_data[-16:] == '1111111111111110':
                    print("[+] End marker found!")
                    binary_data = binary_data[:-16]
                    break
        else:
            continue
        break

    print(f"[*] Extracted {len(binary_data)} bits")

    # Convert binary to text
    message = ""
    for i in range(0, len(binary_data), 8):
        if i + 8 <= len(binary_data):
            byte = binary_data[i:i+8]
            char_code = int(byte, 2)
            if 32 <= char_code <= 126:  # Printable ASCII
                message += chr(char_code)

    return message

def check_png_metadata(image_path):
    """Check PNG metadata for hints"""
    print("\n[*] Checking PNG metadata...")
    img = Image.open(image_path)

    if hasattr(img, 'text'):
        print("[+] PNG text chunks found:")
        for key, value in img.text.items():
            print(f"    {key}: {value}")
    else:
        print("[-] No text chunks found")

def check_appended_data(image_path):
    """Check for data appended to end of file"""
    print("\n[*] Checking for appended data...")

    with open(image_path, 'rb') as f:
        data = f.read()

    marker = b'HIDDEN_DATA_START'
    if marker in data:
        idx = data.index(marker)
        hidden = data[idx + len(marker):].decode('utf-8', errors='ignore')
        print(f"[+] Hidden data found: {hidden}")
        return hidden
    else:
        print("[-] No hidden data marker found")
        return None

def main():
    print("=" * 60)
    print(" WorldCup1 CTF Challenge Solver")
    print("=" * 60)

    image_path = 'worldcup1_challenge.png'

    # Step 1: Check metadata
    check_png_metadata(image_path)

    # Step 2: Check appended data
    check_appended_data(image_path)

    # Step 3: Extract from LSB
    print("\n[*] Extracting flag from LSB steganography...")
    flag = extract_lsb_red_channel(image_path)

    print("\n" + "=" * 60)
    if flag:
        print(f"[+] SUCCESS! Flag found: {flag}")
    else:
        print("[-] Failed to extract flag")
    print("=" * 60)

if __name__ == "__main__":
    main()
