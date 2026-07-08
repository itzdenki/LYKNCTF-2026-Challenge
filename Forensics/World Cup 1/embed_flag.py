#!/usr/bin/env python3
"""
Embed flag into worldcup1.png using multiple steganography techniques
"""
from PIL import Image
import struct

def embed_lsb(image_path, output_path, secret_message):
    """Embed message in LSB of red channel"""
    img = Image.open(image_path)

    # Convert to RGB if necessary
    if img.mode != 'RGB':
        img = img.convert('RGB')

    pixels = img.load()
    width, height = img.size

    # Convert message to binary
    binary_message = ''.join(format(ord(c), '08b') for c in secret_message)
    binary_message += '1111111111111110'  # End marker

    message_index = 0

    # Embed in LSB of red channel
    for y in range(height):
        for x in range(width):
            if message_index < len(binary_message):
                r, g, b = pixels[x, y]

                # Modify LSB of red channel
                if binary_message[message_index] == '1':
                    r = r | 1
                else:
                    r = r & ~1

                pixels[x, y] = (r, g, b)
                message_index += 1
            else:
                break
        if message_index >= len(binary_message):
            break

    img.save(output_path)
    print(f"[+] LSB embedding complete: {len(secret_message)} characters embedded")

def add_text_chunk(image_path, output_path, keyword, text):
    """Add text chunk to PNG metadata"""
    img = Image.open(image_path)

    # Add metadata
    from PIL import PngImagePlugin
    meta = PngImagePlugin.PngInfo()
    meta.add_text(keyword, text)
    meta.add_text("Comment", "The score was 3-2 after extra time")
    meta.add_text("Description", "Argentina vs Cabo Verde - World Cup 2026")

    img.save(output_path, pnginfo=meta)
    print(f"[+] Metadata chunk added: {keyword}")

def append_data(image_path, output_path, data):
    """Append data to end of file"""
    with open(image_path, 'rb') as f:
        img_data = f.read()

    # Add marker and data
    marker = b'HIDDEN_DATA_START'
    hidden = marker + data.encode('utf-8')

    with open(output_path, 'wb') as f:
        f.write(img_data)
        f.write(hidden)

    print(f"[+] Data appended to end of file")

def main():
    flag = "LYKNCTF{Argentina3-2CaboVerde}"

    # Step 1: Embed flag in LSB
    print("[*] Embedding flag in LSB of red channel...")
    embed_lsb('worldcup1.png', 'worldcup1_temp1.png', flag)

    # Step 2: Add metadata chunks
    print("[*] Adding PNG metadata...")
    add_text_chunk('worldcup1_temp1.png', 'worldcup1_temp2.png', 'Flag_Hint', 'Look deeper in the red pixels')

    # Step 3: Append additional data
    print("[*] Appending hidden data...")
    hint_text = "Password hint: What was the final score? Format: X-Y"
    append_data('worldcup1_temp2.png', 'worldcup1_challenge.png', hint_text)

    print("\n[+] Challenge image created: worldcup1_challenge.png")
    print(f"[+] Flag embedded: {flag}")
    print("[+] Multiple layers of steganography applied:")
    print("    1. LSB in red channel")
    print("    2. PNG metadata chunks")
    print("    3. Data appended to file end")

if __name__ == "__main__":
    main()
