#ifndef ANTIDBG_H
#define ANTIDBG_H
/*
 * Anti-debug: returns a status byte, 0 on a clean run, non-zero under a
 * debugger. The byte is folded into BOTH the keygen seed and the flag KDF,
 * so debugging silently poisons every serial and the flag -- no obvious
 * "debugger detected" popup to patch out.
 *
 * Windows-only; included solely by crackme.c (the offline tools pass 0).
 */
#include <windows.h>

/* PEB pointer on x64 lives at gs:[0x60]. */
static unsigned long long adbg_peb(void)
{
    unsigned long long p;
    __asm__ __volatile__ ("movq %%gs:0x60, %0" : "=r"(p));
    return p;
}

typedef LONG (WINAPI *adbg_NtQIP)(HANDLE, ULONG, PVOID, ULONG, PULONG);

static unsigned char lykn_dbg(void)
{
    unsigned char flags = 0;
    unsigned long long peb = adbg_peb();

    /* PEB->BeingDebugged (+0x02) */
    if (*(volatile unsigned char *)(peb + 0x02))
        flags |= 0x01;

    /* PEB->NtGlobalFlag (+0xBC): heap debug bits set when launched under dbg */
    if (*(volatile unsigned int *)(peb + 0xBC) & 0x70)
        flags |= 0x02;

    {
        HMODULE nt = GetModuleHandleA("ntdll.dll");
        adbg_NtQIP q = nt ? (adbg_NtQIP)(void *)GetProcAddress(nt, "NtQueryInformationProcess")
                          : (adbg_NtQIP)0;
        if (q) {
            HANDLE self = (HANDLE)(LONG_PTR)-1;   /* GetCurrentProcess() */
            ULONG_PTR dbgport = 0;
            ULONG dbgflags = 1;
            /* ProcessDebugPort (7): non-zero => debugged */
            if (q(self, 7, &dbgport, sizeof(dbgport), NULL) == 0 && dbgport != 0)
                flags |= 0x04;
            /* ProcessDebugFlags (0x1F): 0 => debugged */
            if (q(self, 0x1F, &dbgflags, sizeof(dbgflags), NULL) == 0 && dbgflags == 0)
                flags |= 0x08;
        }
    }
    return flags;
}

#endif /* ANTIDBG_H */
