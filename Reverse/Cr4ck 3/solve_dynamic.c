/*
 * Dynamic solver for chall8 "Serial Check" -- the INTENDED solve path.
 *
 * It runs the SHIPPED binary and brute-forces the flag one byte at a time
 * using the checker's own early-exit progress oracle. No secrets are baked
 * in: it reads g_progress out of the running process (located via the
 * 8-byte "PRG8LYKN" marker next to it) after each attempt.
 *
 *   build: gcc -O2 -o solve_dynamic.exe solve_dynamic.c -luser32
 *   run  : solve_dynamic.exe [path\to\Serial.exe]
 *
 * This is exactly what a paste-into-ChatGPT attacker cannot do: it requires
 * executing the Windows GUI binary.
 */
#include <windows.h>
#include <stdio.h>
#include <string.h>

static DWORD  g_pid;
static HWND   g_main, g_dlg;

static BOOL CALLBACK findMain(HWND h, LPARAM l){ DWORD p; char t[256]; (void)l;
    GetWindowThreadProcessId(h,&p); if(p==g_pid){ GetWindowTextA(h,t,sizeof(t));
    if(strncmp(t,"LYKNCTF 2026",12)==0) g_main=h; } return TRUE; }
static BOOL CALLBACK findDlg(HWND h, LPARAM l){ DWORD p; char c[64]; (void)l;
    GetWindowThreadProcessId(h,&p); if(p==g_pid){ GetClassNameA(h,c,sizeof(c));
    if(strcmp(c,"#32770")==0) g_dlg=h; } return TRUE; }

static HWND wait_main(void){ int i; for(i=0;i<200;i++){ g_main=0; EnumWindows(findMain,0);
    if(g_main) return g_main; Sleep(25); } return 0; }
static HWND wait_dlg(void){ int i; for(i=0;i<400;i++){ g_dlg=0; EnumWindows(findDlg,0);
    if(g_dlg) return g_dlg; Sleep(5); } return 0; }

/* scan the target's committed writable memory for the progress marker */
static unsigned char *find_progress(HANDLE proc)
{
    unsigned char *addr = 0;
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T got;
    static unsigned char buf[0x10000];
    unsigned char *p = 0;

    while (VirtualQueryEx(proc, p, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_WRITECOPY)) {
            SIZE_T off, n = mbi.RegionSize;
            unsigned char *base = (unsigned char *)mbi.BaseAddress;
            for (off = 0; off < n; off += sizeof(buf)) {
                SIZE_T want = (n - off) < sizeof(buf) ? (n - off) : sizeof(buf);
                SIZE_T i;
                if (!ReadProcessMemory(proc, base + off, buf, want, &got)) break;
                for (i = 0; i + 8 <= got; i++)
                    if (memcmp(buf + i, "PRG8LYKN", 8) == 0)
                        return base + off + i + 8;   /* the int right after */
            }
        }
        p = (unsigned char *)mbi.BaseAddress + mbi.RegionSize;
        if (p == 0) break;
    }
    (void)addr;
    return 0;
}

static void type_serial(HWND edit, const char *s)
{
    SendMessageA(edit, 0x00B1 /*EM_SETSEL*/, 0, -1);
    SendMessageA(edit, 0x0303 /*WM_CLEAR*/, 0, 0);
    for (; *s; s++) SendMessageA(edit, WM_CHAR, (WPARAM)(unsigned char)*s, 0);
}

int main(int argc, char **argv)
{
    const char *exe = (argc > 1) ? argv[1] : "dist\\Serial.exe";
    STARTUPINFOA si; PROCESS_INFORMATION pi;
    HWND edit, btn;
    unsigned char *prog_addr;
    char solved[25]; int i, c;

    ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si);
    if (!CreateProcessA(exe, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        printf("CreateProcess failed: %lu\n", GetLastError()); return 1;
    }
    g_pid = pi.dwProcessId;
    if (!wait_main()) { printf("no window\n"); TerminateProcess(pi.hProcess,0); return 1; }
    edit = GetDlgItem(g_main, 1001);
    btn  = GetDlgItem(g_main, 1002);

    prog_addr = find_progress(pi.hProcess);
    if (!prog_addr) { printf("marker not found\n"); TerminateProcess(pi.hProcess,0); return 1; }
    printf("[*] progress oracle @ %p\n", (void *)prog_addr);

    memset(solved, 0, sizeof(solved));
    for (i = 0; i < 24; i++) {
        int found = -1;
        for (c = 0x20; c <= 0x7E; c++) {
            char attempt[40]; int p = 0, k; SIZE_T got;
            memcpy(attempt, "LYKNCTF{", 8); p = 8;
            for (k = 0; k < i; k++) attempt[p++] = solved[k];
            attempt[p++] = (char)c;
            while (p < 8 + 24) attempt[p++] = 'A';       /* filler */
            attempt[p++] = '}'; attempt[p] = 0;

            type_serial(edit, attempt);
            PostMessageA(g_main, WM_COMMAND, (WPARAM)1002, (LPARAM)btn);
            if (wait_dlg()) {
                int progress = -999;
                ReadProcessMemory(pi.hProcess, prog_addr, &progress, sizeof(progress), &got);
                SendMessageA(g_dlg, WM_CLOSE, 0, 0);
                Sleep(3);
                if (progress > i) { found = c; break; }
            }
        }
        if (found < 0) { printf("[!] stuck at byte %d\n", i); break; }
        solved[i] = (char)found;
        printf("[+] byte %2d = '%c'  -> LYKNCTF{%s\n", i, found, solved);
    }

    printf("\n[+] FLAG: LYKNCTF{%s}\n", solved);
    TerminateProcess(pi.hProcess, 0);
    return 0;
}
