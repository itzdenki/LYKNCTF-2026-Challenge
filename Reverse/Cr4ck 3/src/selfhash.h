#ifndef SELFHASH_H
#define SELFHASH_H
/*
 * SHA-256 of this image's own .text section, read from the loaded PE.
 * Folded into the flag KDF: flip a single code byte (e.g. patch a jne to
 * jmp) and the hash changes -> the derived key changes -> the flag is
 * garbage. The build links with --disable-dynamicbase so the in-memory
 * .text equals the on-disk raw .text (no relocations applied), letting the
 * build-time generator reproduce the exact same hash.
 */
#include <windows.h>
#include "sha256.h"

static void lykn_text_hash(unsigned char out[32])
{
    unsigned char *base = (unsigned char *)GetModuleHandleA(NULL);
    IMAGE_DOS_HEADER  *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS  *nt  = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    unsigned int i;

    for (i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        const unsigned char *nm = sec[i].Name;
        if (nm[0]=='.' && nm[1]=='t' && nm[2]=='e' && nm[3]=='x' && nm[4]=='t') {
            sha256(base + sec[i].VirtualAddress, sec[i].Misc.VirtualSize, out);
            return;
        }
    }
    for (i = 0; i < 32; i++) out[i] = 0;
}

#endif /* SELFHASH_H */
