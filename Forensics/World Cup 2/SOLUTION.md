# WorldCup2 - Solution Guide

## Challenge Overview
**Flag:** `LYKNCTF{RespectToCaboVerde}`  
**Difficulty:** Medium  
**Techniques Used:** File Concatenation, ZIP Archive Hiding, String Markers

---

## Solution Steps

### Step 1: Check File Type
```bash
file worldcup2_challenge.png
```
**Actual output:**
```
worldcup2_challenge.png: JPEG image data, JFIF standard 1.01, aspect ratio,
density 1x1, segment length 16, progressive, precision 8, 1536x2048, components 3
```

Despite the `.png` extension, the file is actually a **JPEG** (starts with
the `FF D8 FF` JPEG/JFIF signature, not PNG's `89 50 4E 47`). That mismatch
is itself a clue — matches the challenge's own hint "Not everything is
what it seems."

### Step 2: Analyze File Structure with Binwalk
```bash
binwalk worldcup2_challenge.png
```

**Verified output** (via a direct signature scan when binwalk isn't
available — same idea binwalk uses internally):
```
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             JPEG image
283620        0x453E4         Zip archive data
```

**What this tells us:**
- The file is actually a JPEG, not a PNG as the extension claims
- There's a ZIP archive appended at offset `0x453E4`

### Step 3: Search for String Hints
```bash
strings worldcup2_challenge.png | grep -i "respect\|cabo\|verde\|flag"
```

**Findings:**
- `RESPECT_TO_CABO_VERDE`
- `The warriors fought bravely`
- `Check the file structure`

### Step 4: Extract the Embedded ZIP Archive

**Method A: Using binwalk**
```bash
binwalk -e worldcup2_challenge.png
```

This will create a directory `_worldcup2_challenge.png.extracted/` containing:
- The extracted ZIP file
- The contents of the ZIP (flag_hidden.txt)

**Method B: Using dd (if you know the offset)**
```bash
# From Step 2, the ZIP starts at offset 283620
dd if=worldcup2_challenge.png of=extracted.zip bs=1 skip=283620
```

**Method C: Manual extraction with Python**
```python
#!/usr/bin/env python3

def extract_zip_from_png(image_path, output_zip):
    with open(image_path, 'rb') as f:
        data = f.read()
    
    # ZIP file signature: PK (0x504B)
    zip_signature = b'PK\x03\x04'
    
    if zip_signature in data:
        zip_start = data.index(zip_signature)
        zip_data = data[zip_start:]
        
        with open(output_zip, 'wb') as f:
            f.write(zip_data)
        
        print(f"[+] ZIP extracted to {output_zip}")
        return True
    else:
        print("[-] No ZIP signature found")
        return False

extract_zip_from_png('worldcup2_challenge.png', 'hidden.zip')
```

### Step 5: Extract Contents from ZIP
```bash
unzip hidden.zip
# or
unzip _worldcup2_challenge.png.extracted/*.zip
```

### Step 6: Read the Flag
```bash
cat flag_hidden.txt
```

**Output:**
```
LYKNCTF{RespectToCaboVerde}
```

---

## Complete Solution Script

```python
#!/usr/bin/env python3
"""Complete solution for WorldCup2 challenge"""

import zipfile
import io

def find_zip_in_file(image_path):
    """Find and extract ZIP archive from PNG"""
    with open(image_path, 'rb') as f:
        data = f.read()
    
    # Look for ZIP signature
    zip_signature = b'PK\x03\x04'
    
    if zip_signature in data:
        zip_start = data.index(zip_signature)
        print(f"[+] ZIP archive found at offset: {zip_start} (0x{zip_start:x})")
        return data[zip_start:]
    
    return None

def extract_flag_from_zip(zip_data):
    """Extract flag from ZIP data"""
    try:
        zip_file = zipfile.ZipFile(io.BytesIO(zip_data))
        
        print(f"[+] ZIP contents: {zip_file.namelist()}")
        
        for filename in zip_file.namelist():
            content = zip_file.read(filename).decode('utf-8')
            print(f"\n[+] Content of {filename}:")
            print(content)
            return content
            
    except Exception as e:
        print(f"[-] Error extracting ZIP: {e}")
        return None

def search_strings(image_path):
    """Search for interesting strings"""
    with open(image_path, 'rb') as f:
        data = f.read()
    
    # Convert to string, ignore errors
    text = data.decode('utf-8', errors='ignore')
    
    keywords = ['RESPECT', 'CABO', 'VERDE', 'FLAG', 'LYKN']
    findings = []
    
    for line in text.split('\x00'):
        for keyword in keywords:
            if keyword in line.upper():
                findings.append(line.strip())
    
    return findings

def main():
    print("[*] WorldCup2 Challenge Solver")
    print("=" * 50)
    
    image_path = 'worldcup2_challenge.png'
    
    # Step 1: Search for string hints
    print("\n[*] Searching for string markers...")
    strings = search_strings(image_path)
    for s in strings:
        if s:
            print(f"[+] Found: {s}")
    
    # Step 2: Find ZIP archive
    print("\n[*] Searching for embedded ZIP archive...")
    zip_data = find_zip_in_file(image_path)
    
    if zip_data:
        # Step 3: Extract flag from ZIP
        print("\n[*] Extracting ZIP contents...")
        flag = extract_flag_from_zip(zip_data)
        
        if flag:
            print("\n" + "=" * 50)
            print(f"[+] FLAG: {flag.strip()}")
    else:
        print("[-] No ZIP archive found")

if __name__ == "__main__":
    main()
```

Save as `solve.py` and run:
```bash
python solve.py
```

---

## Alternative Methods

### Using foremost (file carving)
```bash
foremost -i worldcup2_challenge.png -o output/
cd output/zip/
unzip *.zip
cat flag_hidden.txt
```

### Using hex editor
```bash
xxd worldcup2_challenge.png | grep "504b 0304"
```
The bytes `504b 0304` are the ZIP file signature ("PK\x03\x04"). Note the offset and extract manually.

### Using 7-Zip (Windows)
Simply open `worldcup2_challenge.png` with 7-Zip - it should detect the embedded archive and allow you to extract it directly.

---

## Understanding the Technique

### File Concatenation
- Image formats (this file is actually a **JPEG**, marked by its `FF D8
  FF` header, ending with an `FF D9` EOI marker; the same idea applies to
  PNG's `IEND` chunk) have a defined structure marking where the image
  data ends
- Data appended after that point is ignored by image viewers and decoders
- A ZIP archive can be appended after the image data
- The file still opens fine as an image
- But tools like binwalk (or a plain signature scan) detect the hidden ZIP

### Why This Works
1. **Image viewers/decoders** stop reading at the image's own end marker,
   ignoring extra trailing bytes
2. **The `file` command** identifies the file by its *header* signature —
   here it correctly reports JPEG, regardless of the misleading `.png`
   extension
3. **ZIP readers** can find archives by signature, regardless of position
   in the file
4. **Forensics tools** scan the entire file structure, not just the
   header

---

## Tools Reference

- **binwalk**: Firmware/file analysis tool, detects embedded files
- **foremost**: File carving tool based on headers/footers
- **strings**: Extract printable strings from binary files
- **xxd**: Hex dump viewer
- **unzip**: ZIP archive extraction
- **7-Zip**: GUI tool that can detect embedded archives
- **Python zipfile**: Library for ZIP manipulation

---

## Key Takeaways

1. **File structure analysis** - Always check the entire file, not just the visible content
2. **Signature scanning** - Look for magic bytes (ZIP: `PK`, PNG: `\x89PNG`, etc.)
3. **Multiple file formats** - A file can be valid in multiple formats simultaneously
4. **Tool selection** - Different tools reveal different aspects of the file

---

## Flag
`LYKNCTF{RespectToCaboVerde}`
