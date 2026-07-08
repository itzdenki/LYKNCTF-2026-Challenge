# WorldCup1 - Solution Guide

## Challenge Overview
**Flag:** `LYKNCTF{Argentina3-2CaboVerde}`  
**Difficulty:** Medium  
**Techniques Used:** LSB Steganography, PNG Metadata, Data Appending

---

## Solution Steps

### Step 1: Check File Type
```bash
file worldcup1_challenge.png
```
**Output:** PNG image data

### Step 2: Analyze PNG Metadata
```bash
pngcheck -v worldcup1_challenge.png
# or
exiftool worldcup1_challenge.png
```

**What to look for:**
- PNG text chunks with hints
- Look for keywords like "Flag_Hint", "Comment", "Description"
- You should see: "The score was 3-2 after extra time"

**Findings:**
- Comment: "The score was 3-2 after extra time"
- Flag_Hint: "Look deeper in the red pixels"

### Step 3: Check for Appended Data
```bash
strings worldcup1_challenge.png | tail -20
```

**What to find:**
- Look for "HIDDEN_DATA_START"
- You'll see: "Password hint: What was the final score? Format: X-Y"

### Step 4: Extract LSB Data from Red Channel

**Method A: Using zsteg (if available)**
```bash
zsteg worldcup1_challenge.png
```

**Method B: Using Python script**
```python
#!/usr/bin/env python3
from PIL import Image

def extract_lsb(image_path):
    img = Image.open(image_path)
    pixels = img.load()
    width, height = img.size
    
    binary_data = ""
    
    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y]
            binary_data += str(r & 1)
    
    # Convert binary to text
    message = ""
    for i in range(0, len(binary_data), 8):
        byte = binary_data[i:i+8]
        if len(byte) == 8:
            char = chr(int(byte, 2))
            if char == '\xfe':  # End marker
                break
            if 32 <= ord(char) <= 126:
                message += char
            else:
                break
    
    return message

flag = extract_lsb('worldcup1_challenge.png')
print(f"Extracted flag: {flag}")
```

Save as `extract_lsb.py` and run:
```bash
python extract_lsb.py
```

**Output:**
```
Extracted flag: LYKNCTF{Argentina3-2CaboVerde}
```

---

## Alternative Tools

### Using stegsolve (Java-based)
1. Open `worldcup1_challenge.png` in stegsolve
2. Navigate through color planes
3. Look at Red plane 0 (LSB)
4. Extract data

### Using hex editor
```bash
xxd worldcup1_challenge.png | tail -100
```
Look for the hidden data marker and appended information.

---

## Complete Solution Script

```python
#!/usr/bin/env python3
"""Complete solution for WorldCup1 challenge"""

from PIL import Image
import struct

def extract_lsb(image_path):
    """Extract message from LSB of red channel"""
    img = Image.open(image_path)
    pixels = img.load()
    width, height = img.size
    
    binary_data = ""
    
    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y]
            binary_data += str(r & 1)
            
            # Check if we have enough for a character
            if len(binary_data) >= 16:
                # Check for end marker
                if binary_data[-16:] == '1111111111111110':
                    break
    
    # Convert binary to text
    message = ""
    for i in range(0, len(binary_data) - 16, 8):
        byte = binary_data[i:i+8]
        char = chr(int(byte, 2))
        message += char
    
    return message

def read_appended_data(image_path):
    """Read data appended to end of file"""
    with open(image_path, 'rb') as f:
        data = f.read()
    
    marker = b'HIDDEN_DATA_START'
    if marker in data:
        idx = data.index(marker)
        hidden = data[idx + len(marker):].decode('utf-8', errors='ignore')
        return hidden
    return None

def main():
    print("[*] WorldCup1 Challenge Solver")
    print("=" * 50)
    
    # Extract from LSB
    print("\n[*] Extracting from LSB...")
    flag = extract_lsb('worldcup1_challenge.png')
    print(f"[+] Flag found: {flag}")
    
    # Read appended data
    print("\n[*] Checking appended data...")
    hidden = read_appended_data('worldcup1_challenge.png')
    if hidden:
        print(f"[+] Hidden message: {hidden}")
    
    print("\n" + "=" * 50)
    print(f"[+] FLAG: {flag}")

if __name__ == "__main__":
    main()
```

---

## Key Takeaways

1. **Multiple layers** - This challenge requires checking multiple steganography techniques
2. **Metadata hints** - PNG chunks provide clues about where to look
3. **LSB steganography** - The main flag is hidden in the least significant bits of the red channel
4. **File structure** - Additional data appended beyond the PNG structure

---

## Tools Reference

- **pngcheck**: PNG file structure checker
- **exiftool**: Metadata extraction
- **strings**: Extract printable strings from binary
- **zsteg**: Ruby-based PNG/BMP steganography detector
- **xxd**: Hex dump tool
- **Python + PIL/Pillow**: Custom LSB extraction

---

## Flag
`LYKNCTF{Argentina3-2CaboVerde}`
