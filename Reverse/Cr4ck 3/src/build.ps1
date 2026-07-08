# Two-pass build for LYKNCTF 2026 chall8 "Serial Check".
# Requires MSYS2 UCRT64 (gcc/windres/objcopy) + Python on PATH.
#
# The IV mixes SHA256(.text), so build once to measure .text, regenerate the
# checkpoints against that hash, then rebuild. Checkpoints live in .rdata, so
# .text is byte-identical across passes (verified). ASLR is disabled so the
# runtime self-hash matches the on-disk .text.
$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

$GEN = Join-Path $PSScriptRoot "..\tools\gen.py"
$OUT = Join-Path $PSScriptRoot "..\dist\Serial.exe"
New-Item -ItemType Directory -Force -Path (Split-Path $OUT) | Out-Null
$LD  = @("-Wl,--disable-dynamicbase","-Wl,--disable-high-entropy-va")
$LIB = @("-luser32","-lgdi32","-lcomctl32")

function TextHash([string]$exe) {
    $bin = "$exe.text.bin"
    objcopy -O binary --only-section=.text $exe $bin
    $h = (Get-FileHash -Algorithm SHA256 $bin).Hash
    Remove-Item $bin -ErrorAction SilentlyContinue
    return $h
}

Write-Host "[*] Pass 0: placeholder check_data.h (dummy IV)..."
python $GEN | Out-Null

Write-Host "[*] Compiling resources..."
windres -i crackme8.rc -o crackme8_res.o -O coff

Write-Host "[*] Pass 1: compile to measure .text..."
gcc -O2 -s -mwindows @LD crackme8.c crackme8_res.o -o pass1.exe @LIB

Write-Host "[*] Regenerating checkpoints against pass1 .text hash..."
python $GEN pass1.exe | Out-Null

Write-Host "[*] Pass 2: final build..."
gcc -O2 -s -mwindows @LD crackme8.c crackme8_res.o -o "$OUT" @LIB

Write-Host "[*] Verifying .text identical across passes..."
$h1 = TextHash "pass1.exe"; $h2 = TextHash "$OUT"
if ($h1 -eq $h2) { Write-Host "[+] .text stable: $h1" }
else { Write-Host "[!] .text DIFFERS`n  pass1 $h1`n  final $h2"; exit 1 }

Remove-Item pass1.exe, crackme8_res.o -ErrorAction SilentlyContinue
Write-Host ("[+] Built: {0}  ({1} bytes)" -f $OUT, (Get-Item $OUT).Length)
