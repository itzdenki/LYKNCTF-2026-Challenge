# Two-pass build for LYKNCTF 2026 chall7 "License Activation".
# Requires MSYS2 UCRT64 (gcc/windres/objcopy) + Python on PATH.
#
# The VM bytecode is XOR-encrypted with a key that folds in SHA256(.text),
# so we build once to measure .text, re-encrypt the bytecode against that
# hash, then rebuild. The encrypted bytecode lives in .rdata, so .text is
# byte-identical across passes (verified). ASLR is disabled so the runtime
# self-hash matches the on-disk .text the generator hashed.
$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

$ASM = Join-Path $PSScriptRoot "..\tools\asm.py"
$OUT = Join-Path $PSScriptRoot "..\dist\Activator.exe"
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

Write-Host "[*] Pass 0: emit placeholder vm_program.h (zero .text hash)..."
python $ASM

Write-Host "[*] Compiling resources..."
windres -i crackme7.rc -o crackme7_res.o -O coff

Write-Host "[*] Pass 1: compile to measure .text..."
gcc -O2 -s -mwindows @LD crackme7.c crackme7_res.o -o pass1.exe @LIB

Write-Host "[*] Re-encrypting bytecode against pass1 .text hash..."
python $ASM pass1.exe

Write-Host "[*] Pass 2: final build..."
gcc -O2 -s -mwindows @LD crackme7.c crackme7_res.o -o "$OUT" @LIB

Write-Host "[*] Verifying .text identical across passes..."
$h1 = TextHash "pass1.exe"
$h2 = TextHash "$OUT"
if ($h1 -eq $h2) {
    Write-Host "[+] .text stable: $h1"
} else {
    Write-Host "[!] .text DIFFERS -> self-hash decode will fail!"
    Write-Host "    pass1: $h1`n    final: $h2"; exit 1
}

Remove-Item pass1.exe, crackme7_res.o -ErrorAction SilentlyContinue
Write-Host ("[+] Built: {0}  ({1} bytes)" -f $OUT, (Get-Item $OUT).Length)
