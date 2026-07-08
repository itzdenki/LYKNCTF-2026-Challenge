/*
 * LYKNCTF 2026 - "License Activation" (chall7)
 * Reverse Engineering challenge (very hard, anti-LLM).
 *
 * The activation key IS the flag: LYKNCTF{ + 32 bytes + }. Those 32 bytes
 * are the plaintext of a bespoke ARX permutation whose output is compared
 * against an embedded target. The permutation + comparison run inside a
 * custom BYTECODE VM whose program is stored XOR-encrypted; the decode key
 * folds in SHA256(.text) (anti-tamper) and an anti-debug byte. Nothing is
 * recognizable to a library matcher, and the flag is the preimage of the
 * target -- recover it by understanding and inverting the permutation.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commctrl.h>
#include <string.h>

#include "sha256.h"
#include "antidbg.h"     /* lykn_dbg()        */
#include "selfhash.h"    /* lykn_text_hash()  */
#include "vm.h"          /* vm_execute()      */
#include "vmload.h"      /* vm_decode()       */
#include "vm_program.h"  /* g_prog_enc, g_target_b, PROG_LEN, VM_SALT */

#define ID_EDIT_KEY   1001
#define ID_BTN_CHECK  1002
#define ID_BTN_EXIT   1003
#define IDB_BANNER    2001

#define BANNER_X 10
#define BANNER_Y 10
#define BANNER_W 480
#define BANNER_H 248

static HINSTANCE g_hInst  = NULL;
static HBITMAP   g_hBanner = NULL;
static HFONT     g_hFont   = NULL;

/* ------------------------------------------------------------------ */
static void do_check(HWND hwnd)
{
    char in[128];
    unsigned char inner[32];
    unsigned int inw[8], target[8];
    unsigned char th[32], dbg;
    unsigned char prog[PROG_LEN];
    unsigned int acc;
    int n, i;

    n = GetDlgItemTextA(hwnd, ID_EDIT_KEY, in, sizeof(in));

    if (n != 41 || memcmp(in, "LYKNCTF{", 8) != 0 || in[40] != '}') {
        MessageBoxA(hwnd,
            "Activation key format is LYKNCTF{ + 32 chars + }.",
            "License Activation", MB_ICONWARNING | MB_OK);
        return;
    }

    memcpy(inner, in + 8, 32);
    for (i = 0; i < 8; i++) {
        inw[i]    = (unsigned int)inner[4*i] | ((unsigned int)inner[4*i+1] << 8)
                  | ((unsigned int)inner[4*i+2] << 16) | ((unsigned int)inner[4*i+3] << 24);
        target[i] = (unsigned int)g_target_b[4*i] | ((unsigned int)g_target_b[4*i+1] << 8)
                  | ((unsigned int)g_target_b[4*i+2] << 16) | ((unsigned int)g_target_b[4*i+3] << 24);
    }

    dbg = lykn_dbg();
    lykn_text_hash(th);
    vm_decode(g_prog_enc, PROG_LEN, th, dbg, VM_SALT, prog);

    acc = vm_execute(prog, PROG_LEN, inw, target);

    if (acc == 0) {
        MessageBoxA(hwnd,
            "Activation successful!\r\n\r\n"
            "This license key is valid -- and it is your flag.",
            "License Activation - OK", MB_ICONINFORMATION | MB_OK);
    } else {
        MessageBoxA(hwnd,
            "Invalid activation key.\r\nKeep reversing.",
            "License Activation - FAILED", MB_ICONERROR | MB_OK);
    }

    SecureZeroMemory(prog, sizeof(prog));
    SecureZeroMemory(inner, sizeof(inner));
    SecureZeroMemory(inw, sizeof(inw));
}

/* ------------------------------------------------------------------ */
static void set_font(HWND h) { SendMessageA(h, WM_SETFONT, (WPARAM)g_hFont, TRUE); }

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_CREATE: {
        HWND h;
        g_hBanner = LoadBitmapA(g_hInst, MAKEINTRESOURCEA(IDB_BANNER));
        g_hFont = CreateFontA(-15, 0, 0, 0, FW_NORMAL, 0, 0, 0,
                              DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                              CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                              DEFAULT_PITCH | FF_SWISS, "Segoe UI");

        h = CreateWindowExA(0, "STATIC", "Activation Key:", WS_CHILD | WS_VISIBLE,
                            BANNER_X, 268, 120, 20, hwnd, NULL, g_hInst, NULL);
        set_font(h);
        h = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
                            WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
                            BANNER_X, 290, 480, 24, hwnd,
                            (HMENU)ID_EDIT_KEY, g_hInst, NULL);
        set_font(h);

        h = CreateWindowExA(0, "BUTTON", "Check it!",
                            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
                            130, 330, 110, 32, hwnd,
                            (HMENU)ID_BTN_CHECK, g_hInst, NULL);
        set_font(h);
        h = CreateWindowExA(0, "BUTTON", "Exit",
                            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                            260, 330, 110, 32, hwnd,
                            (HMENU)ID_BTN_EXIT, g_hInst, NULL);
        set_font(h);
        return 0;
    }

    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        if (g_hBanner) {
            HDC mem = CreateCompatibleDC(hdc);
            HGDIOBJ old = SelectObject(mem, g_hBanner);
            BitBlt(hdc, BANNER_X, BANNER_Y, BANNER_W, BANNER_H, mem, 0, 0, SRCCOPY);
            SelectObject(mem, old);
            DeleteDC(mem);
        }
        EndPaint(hwnd, &ps);
        return 0;
    }

    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case ID_BTN_CHECK: do_check(hwnd);      return 0;
        case ID_BTN_EXIT:  DestroyWindow(hwnd); return 0;
        }
        break;

    case WM_CTLCOLORSTATIC:
        SetBkMode((HDC)wp, TRANSPARENT);
        return (LRESULT)GetSysColorBrush(COLOR_BTNFACE);

    case WM_DESTROY:
        if (g_hBanner) DeleteObject(g_hBanner);
        if (g_hFont)   DeleteObject(g_hFont);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcA(hwnd, msg, wp, lp);
}

/* ------------------------------------------------------------------ */
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR cmd, int show)
{
    WNDCLASSEXA wc;
    HWND hwnd;
    MSG msg;
    RECT rc;
    int win_w, win_h;
    INITCOMMONCONTROLSEX icc;
    DWORD style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX;

    (void)hPrev; (void)cmd;
    g_hInst = hInst;

    icc.dwSize = sizeof(icc);
    icc.dwICC  = ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icc);

    ZeroMemory(&wc, sizeof(wc));
    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInst;
    wc.hCursor       = LoadCursorA(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = "LYKN_Activator";
    wc.hIcon         = LoadIconA(NULL, IDI_APPLICATION);
    RegisterClassExA(&wc);

    rc.left = 0; rc.top = 0; rc.right = 500; rc.bottom = 378;
    AdjustWindowRect(&rc, style, FALSE);
    win_w = rc.right - rc.left;
    win_h = rc.bottom - rc.top;

    hwnd = CreateWindowExA(0, "LYKN_Activator",
                           "LYKNCTF 2026 :: License Activation",
                           style, CW_USEDEFAULT, CW_USEDEFAULT,
                           win_w, win_h, NULL, NULL, hInst, NULL);
    if (!hwnd) return 1;

    ShowWindow(hwnd, show);
    UpdateWindow(hwnd);

    while (GetMessageA(&msg, NULL, 0, 0) > 0) {
        if (!IsDialogMessageA(hwnd, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageA(&msg);
        }
    }
    return (int)msg.wParam;
}
