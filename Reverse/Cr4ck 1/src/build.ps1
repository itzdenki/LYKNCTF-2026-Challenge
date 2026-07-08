# Two-pass build for LYKNCTF 2026 KeygenMe (v2, very hard).
# Requires MSYS2 UCRT64 (gcc + windres + objcopy) on PATH.
#
# Why two passes: the flag key mixes SHA256(.text). We build once to
# measure .text, encrypt the flag against that hash, then rebuild. The
# flag ciphertext lives in .rdata, so .text is byte-identical across the
# two passes (verified at the end). ASLR is disabled so the in-memory
# .text equals the on-disk .text the generator hashed.
$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

$OUT   = Join-Path $PSScriptRoot "..\dist\KeygenMe.exe"
New-Item -ItemType Directory -Force -Path (Split-Path $OUT) | Out-Null
$LDFLAGS = @("-Wl,--disable-dynamicbase","-Wl,--disable-high-entropy-va")
$LIBS  = @("-luser32","-lgdi32","-lcomctl32")

function TextHash([string]$exe) {
    $bin = "$exe.text.bin"
    objcopy -O binary --only-section=.text $exe $bin
    $h = (Get-FileHash -Algorithm SHA256 $bin).Hash
    Remove-Item $bin -ErrorAction SilentlyContinue
    return $h
}

Write-Host "[*] Building flag generator (host tool)..."
gcc -O2 -o gen_flag.exe gen_flag.c

Write-Host "[*] Pass 0: emit placeholder flag_enc.h (zero .text hash)..."
.\gen_flag.exe            # no arg -> dummy, correct sizes

Write-Host "[*] Compiling resources..."
windres -i crackme.rc -o crackme_res.o -O coff

Write-Host "[*] Pass 1: compile to measure .text..."
gcc -O2 -s -mwindows @LDFLAGS crackme.c crackme_res.o -o pass1.exe @LIBS

Write-Host "[*] Encrypting flag against pass1 .text hash..."
.\gen_flag.exe pass1.exe  # real flag_enc.h

Write-Host "[*] Pass 2: final build..."
gcc -O2 -s -mwindows @LDFLAGS crackme.c crackme_res.o -o "$OUT" @LIBS

Write-Host "[*] Verifying .text is identical across passes..."
$h1 = TextHash "pass1.exe"
$h2 = TextHash "$OUT"
if ($h1 -eq $h2) {
    Write-Host "[+] .text stable: $h1"
} else {
    Write-Host "[!] .text DIFFERS between passes -> self-hash will not match!"
    Write-Host "    pass1: $h1"
    Write-Host "    final: $h2"
    exit 1
}

Remove-Item pass1.exe, crackme_res.o -ErrorAction SilentlyContinue
if (Test-Path $OUT) {
    Write-Host ("[+] Built: {0}  ({1} bytes)" -f $OUT, (Get-Item $OUT).Length)
} else {
    Write-Host "[!] Build failed."; exit 1
}
