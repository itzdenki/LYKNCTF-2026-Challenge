#!/usr/bin/env python3
"""
WorldCup2 Challenge Solver
Extracts flag from embedded ZIP archive in PNG image
"""

import zipfile
import io

def analyze_file_structure(image_path):
    """Analyze file for embedded data"""
    print(f"[*] Analyzing file: {image_path}")

    with open(image_path, 'rb') as f:
        data = f.read()

    print(f"[*] File size: {len(data)} bytes")

    # Check for common file signatures
    signatures = {
        b'\x89PNG': 'PNG image',
        b'PK\x03\x04': 'ZIP archive',
        b'\xFF\xD8\xFF': 'JPEG image',
        b'GIF8': 'GIF image'
    }

    print("\n[*] Searching for file signatures...")
    found_signatures = []

    for sig, desc in signatures.items():
        idx = data.find(sig)
        if idx != -1:
            print(f"[+] {desc} signature found at offset {idx} (0x{idx:x})")
            found_signatures.append((sig, desc, idx))

    return data, found_signatures

def search_interesting_strings(data):
    """Search for interesting strings in the file"""
    print("\n[*] Searching for interesting strings...")

    text = data.decode('utf-8', errors='ignore')
    keywords = ['LYKN', 'FLAG', 'RESPECT', 'CABO', 'VERDE', 'CTF']

    findings = set()
    for line in text.split('\x00'):
        line = line.strip()
        if any(kw in line.upper() for kw in keywords):
            if 5 < len(line) < 200 and line.isprintable():
                findings.add(line)

    if findings:
        print("[+] Interesting strings found:")
        for finding in sorted(findings):
            print(f"    {finding}")
    else:
        print("[-] No interesting strings found")

def extract_embedded_zip(data):
    """Extract embedded ZIP archive"""
    print("\n[*] Attempting to extract embedded ZIP...")

    zip_sig = b'PK\x03\x04'
    zip_start = data.find(zip_sig)

    if zip_start == -1:
        print("[-] No ZIP archive found")
        return None

    print(f"[+] ZIP archive found at offset {zip_start}")

    # Extract ZIP data
    zip_data = data[zip_start:]

    try:
        zip_file = zipfile.ZipFile(io.BytesIO(zip_data))
        print(f"[+] ZIP archive is valid")
        print(f"[+] Files in archive: {zip_file.namelist()}")

        # Extract all files
        results = {}
        for filename in zip_file.namelist():
            content = zip_file.read(filename)
            results[filename] = content
            print(f"\n[+] Extracted: {filename}")
            print(f"    Size: {len(content)} bytes")

            # Try to decode as text
            try:
                text_content = content.decode('utf-8')
                print(f"    Content: {text_content}")
            except:
                print(f"    Content: [binary data]")

        return results

    except zipfile.BadZipFile:
        print("[-] Invalid ZIP archive")
        return None

def main():
    print("=" * 60)
    print(" WorldCup2 CTF Challenge Solver")
    print("=" * 60)

    image_path = 'worldcup2_challenge.png'

    # Step 1: Analyze file structure
    data, signatures = analyze_file_structure(image_path)

    # Step 2: Search for interesting strings
    search_interesting_strings(data)

    # Step 3: Extract embedded ZIP
    results = extract_embedded_zip(data)

    # Step 4: Display results
    print("\n" + "=" * 60)
    if results:
        print("[+] SUCCESS! Files extracted from ZIP:")
        for filename, content in results.items():
            try:
                text = content.decode('utf-8')
                if 'LYKN' in text or 'FLAG' in text.upper():
                    print(f"\n[+] FLAG FOUND in {filename}:")
                    print(f"    {text}")
            except:
                pass
    else:
        print("[-] Failed to extract flag")
    print("=" * 60)

if __name__ == "__main__":
    main()
