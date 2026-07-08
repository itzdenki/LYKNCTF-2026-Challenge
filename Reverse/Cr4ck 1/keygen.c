/*
 * Official keygen for LYKNCTF 2026 "Loi Yeu Kho Noi" KeygenMe (v2).
 * Shares keygen_core.h with the binary, so output is guaranteed correct.
 *
 *   build: gcc -O2 -o keygen.exe keygen.c
 *   usage: keygen.exe <username>
 *
 * dbg is 0 here: a keygen targets the CLEAN (non-debugged) program.
 */
#include <stdio.h>
#include <string.h>
#include "src/keygen_core.h"

int main(int argc, char **argv)
{
    char key[32];
    const char *user;
    int len;

    if (argc < 2) {
        printf("usage: %s <username>\n", argv[0]);
        return 1;
    }
    user = argv[1];
    len  = (int)strlen(user);
    if (len < 4) {
        printf("[!] username must be at least 4 characters\n");
        return 1;
    }
    lykn_keygen(user, len, 0, key);
    printf("Username : %s\n", user);
    printf("License  : %s\n", key);
    return 0;
}
