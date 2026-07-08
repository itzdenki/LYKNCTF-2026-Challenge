/*
 * LYKNCTF 2026 - "Serial Check" (chall8) -- stage 2 skeleton.
 *
 * Single-input GUI. The flag is LYKNCTF{ + 24 bytes + }. The checker rolls a
 * one-way MIX over the input and compares 16-bit checkpoints byte by byte,
 * bailing at the first wrong byte. g_state.progress (next to a scan marker)
 * exposes how many leading bytes matched -- the dynamic solve oracle.
 *
 * Later stages virtualize MIX (self-modifying VM + VEH) and derive IV at
 * runtime, so the only practical solve is to RUN it and read the oracle.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commctrl.h>
#include <string.h>

#include "sha256.h"
#include "selfhash.h"       /* lykn_text_hash() */
#include "tls.h"            /* g_tls_seed (set pre-main) */
#include "vm8.h"            /* run_check_vm(), + check_data.h */

#define ID_EDIT_KEY  1001
#define ID_BTN_CHECK 1002
#define ID_BTN_EXIT  1003
#define IDB_BANNER   2001

#define BANNER_X 10
#define BANNER_Y 10
#define BANNER_W 480
#define BANNER_H 248

static HINSTANCE g_hInst = NULL;
static HBITMAP   g_hBanner = NULL;
static HFONT     g_hFont = NULL;

/* progress oracle: an 8-byte marker so a dynamic solver can locate the
 * progress counter in memory, then the counter itself. */
static volatile struct {
    char marker[8];
    int progress;
} g_state = { { 'P','R','G','8','L','Y','K','N' }, -1 };
/* take the address so the whole struct (marker included) is emitted and not
 * split/eliminated by the optimizer. */
void *const g_state_anchor __attribute__((used)) = (void *)&g_state;

/* ------------------------------------------------------------------ */
static void do_check(HWND hwnd)
{
    char in[128];
    unsigned char inner[CHECK_N];
    unsigned char th[32];
    unsigned int iv;
    int n, p;

    n = GetDlgItemTextA(hwnd, ID_EDIT_KEY, in, sizeof(in));

    if (n != 8 + CHECK_N + 1 || memcmp(in, "LYKNCTF{", 8) != 0 || in[8 + CHECK_N] != '}') {
        g_state.progress = -1;
        MessageBoxA(hwnd,
            "Serial format is LYKNCTF{ + 24 chars + }.",
            "Serial Check", MB_ICONWARNING | MB_OK);
        return;
    }

    /* IV derived at runtime: SHA256(.text) XOR the pre-main TLS seed. */
    lykn_text_hash(th);
    iv = ((unsigned int)th[0] | ((unsigned int)th[1] << 8)
        | ((unsigned int)th[2] << 16) | ((unsigned int)th[3] << 24)) ^ g_tls_seed;

    memcpy(inner, in + 8, CHECK_N);
    p = run_check_vm(inner, CHECK_N, iv, g_chk);
    g_state.progress = p;

    if (p == CHECK_N) {
        MessageBoxA(hwnd,
            "Serial accepted!\r\n\r\nThat serial is your flag.",
            "Serial Check - OK", MB_ICONINFORMATION | MB_OK);
    } else {
        MessageBoxA(hwnd,
            "Invalid serial.\r\nKeep reversing.",
            "Serial Check - FAILED", MB_ICONERROR | MB_OK);
    }
    SecureZeroMemory(inner, sizeof(inner));
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
        h = CreateWindowExA(0, "STATIC", "Serial:", WS_CHILD | WS_VISIBLE,
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
    icc.dwSize = sizeof(icc); icc.dwICC = ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icc);

    ZeroMemory(&wc, sizeof(wc));
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.hCursor = LoadCursorA(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = "LYKN_Gauntlet";
    wc.hIcon = LoadIconA(NULL, IDI_APPLICATION);
    RegisterClassExA(&wc);

    rc.left = 0; rc.top = 0; rc.right = 500; rc.bottom = 378;
    AdjustWindowRect(&rc, style, FALSE);
    win_w = rc.right - rc.left; win_h = rc.bottom - rc.top;

    hwnd = CreateWindowExA(0, "LYKN_Gauntlet",
                           "LYKNCTF 2026 :: Serial Check",
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
