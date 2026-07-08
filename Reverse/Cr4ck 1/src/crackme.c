/*
 * LYKNCTF 2026 - "Loi Yeu Kho Noi" KeygenMe  (v2, very hard)
 * Reverse Engineering challenge.
 *
 * The flag is NOT gated by a branch and is NOT stored in any recoverable
 * form. It is the plaintext of an AEAD-ish scheme whose key is derived at
 * runtime from EVERYTHING that must be right:
 *
 *     K = SHA256( username || key || SHA256(.text) || antidebug_byte )
 *
 * So: reading the ciphertext is useless, patching the compare is useless
 * (it changes SHA256(.text) and corrupts K), calling the decrypt is useless
 * (needs the exact inputs), and tracing under a debugger poisons K. Only a
 * clean, un-patched binary fed the hidden target user + its correct serial
 * decrypts to something whose tag validates.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commctrl.h>
#include <string.h>

#define KG_NOINLINE __attribute__((noinline))   /* keep clean function boundaries */
#include "keygen_core.h"    /* lykn_keygen() (target) + hidden-user deobfuscation */
#include "sha256.h"
#include "flagcrypt.h"      /* lykn_derive_key / lykn_keystream / lykn_tag         */
#include "antidbg.h"        /* lykn_dbg()                                          */
#include "selfhash.h"       /* lykn_text_hash()                                    */
#include "flag_enc.h"       /* g_ct[], g_tag[], g_encu[], G_ENCU_LEN               */

/* ------------------------------------------------------------------ */
/* Control / resource identifiers                                     */
/* ------------------------------------------------------------------ */
#define ID_EDIT_USER   1001
#define ID_EDIT_KEY    1002
#define ID_BTN_CHECK   1003
#define ID_BTN_EXIT    1004
#define IDB_BANNER     2001

#define BANNER_X   10
#define BANNER_Y   10
#define BANNER_W   480
#define BANNER_H   248

static HINSTANCE g_hInst  = NULL;
static HBITMAP   g_hBanner = NULL;
static HFONT     g_hFont   = NULL;

/* ------------------------------------------------------------------ */
/* Validation                                                         */
/*                                                                    */
/* The keygen the players must reverse is lykn_keygen() in            */
/* keygen_core.h. The flag is produced purely by decrypting g_ct with */
/* a key derived from the typed inputs + self-hash + anti-debug byte; */
/* the string compares below only drive the on-screen feedback.       */
/* ------------------------------------------------------------------ */
static void do_check(HWND hwnd)
{
    char user[128];
    char key[64];
    char serial[32];
    char plainU[160];
    unsigned char th[32], K[32], ks[FLAG_CTLEN], pt[FLAG_CTLEN], tg[8];
    unsigned char dbg;
    int ulen, klen, i, flen;

    ulen = GetDlgItemTextA(hwnd, ID_EDIT_USER, user, sizeof(user));
    klen = GetDlgItemTextA(hwnd, ID_EDIT_KEY,  key,  sizeof(key));

    if (ulen < 4) {
        MessageBoxA(hwnd, "Username must be at least 4 characters.",
                    "Invalid input", MB_ICONWARNING | MB_OK);
        return;
    }
    if (klen == 0) {
        MessageBoxA(hwnd, "Please enter a license key.",
                    "Invalid input", MB_ICONWARNING | MB_OK);
        return;
    }

    /* normalise entered key to upper-case so 'abcd' == 'ABCD' */
    for (i = 0; key[i]; i++)
        if (key[i] >= 'a' && key[i] <= 'z')
            key[i] = (char)(key[i] - 'a' + 'A');
    klen = (int)strlen(key);

    dbg = lykn_dbg();          /* != 0 under a debugger -> poisons serial + K */

    /* Gate 1: hidden account. Recovered from the obfuscated blob. */
    lykn_obf_user(g_encu, G_ENCU_LEN, (unsigned char *)plainU);
    plainU[G_ENCU_LEN] = '\0';
    if (lstrcmpA(user, plainU) != 0) {
        SecureZeroMemory(plainU, sizeof(plainU));
        MessageBoxA(hwnd,
            "Unknown account.\r\nThis license desk only serves one client.",
            "Check it! - FAILED", MB_ICONERROR | MB_OK);
        return;
    }
    SecureZeroMemory(plainU, sizeof(plainU));

    /* Gate 2: correct serial for this account (computed with dbg). */
    lykn_keygen(user, ulen, dbg, serial);
    if (lstrcmpA(key, serial) != 0) {
        SecureZeroMemory(serial, sizeof(serial));
        MessageBoxA(hwnd,
            "Wrong license key for this account.\r\nKeep reversing!",
            "Check it! - FAILED", MB_ICONERROR | MB_OK);
        return;
    }
    SecureZeroMemory(serial, sizeof(serial));

    /* Unlock: key = SHA256(user || key || SHA256(.text) || dbg). The tag
     * only validates on a clean, un-patched binary with the right inputs. */
    lykn_text_hash(th);
    lykn_derive_key((const unsigned char *)user, ulen,
                    (const unsigned char *)key, klen, th, dbg, K);
    lykn_keystream(K, ks);
    for (i = 0; i < FLAG_CTLEN; i++) pt[i] = g_ct[i] ^ ks[i];

    flen = 0;
    while (flen < FLAG_CTLEN && pt[flen] != 0) flen++;
    lykn_tag(pt, flen, tg);

    if (flen < FLAG_CTLEN && memcmp(tg, g_tag, 8) == 0) {
        char msg[256];
        pt[flen] = '\0';
        wsprintfA(msg,
            "Access granted!\r\n\r\n"
            "Welcome, %s.\r\n"
            "Your license is valid.\r\n\r\n"
            "Flag: %s", user, (char *)pt);
        MessageBoxA(hwnd, msg, "Check it! - SUCCESS", MB_ICONINFORMATION | MB_OK);
    } else {
        MessageBoxA(hwnd,
            "License valid, but the vault stays locked.\r\n"
            "(are you being watched?)",
            "Check it! - FAILED", MB_ICONERROR | MB_OK);
    }
    SecureZeroMemory(pt, sizeof(pt));
    SecureZeroMemory(K, sizeof(K));
}

/* ------------------------------------------------------------------ */
/* Window procedure                                                   */
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

        /* labels */
        h = CreateWindowExA(0, "STATIC", "Username:", WS_CHILD | WS_VISIBLE,
                            BANNER_X, 272, 90, 20, hwnd, NULL, g_hInst, NULL);
        set_font(h);
        h = CreateWindowExA(0, "STATIC", "License Key:", WS_CHILD | WS_VISIBLE,
                            BANNER_X, 306, 90, 20, hwnd, NULL, g_hInst, NULL);
        set_font(h);

        /* edit boxes */
        h = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
                            WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
                            110, 270, 380, 24, hwnd,
                            (HMENU)ID_EDIT_USER, g_hInst, NULL);
        set_font(h);
        h = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
                            WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
                            110, 304, 380, 24, hwnd,
                            (HMENU)ID_EDIT_KEY, g_hInst, NULL);
        set_font(h);

        /* buttons */
        h = CreateWindowExA(0, "BUTTON", "Check it!",
                            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
                            110, 342, 120, 32, hwnd,
                            (HMENU)ID_BTN_CHECK, g_hInst, NULL);
        set_font(h);
        h = CreateWindowExA(0, "BUTTON", "Exit",
                            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                            250, 342, 120, 32, hwnd,
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
        case ID_BTN_CHECK: do_check(hwnd);            return 0;
        case ID_BTN_EXIT:  DestroyWindow(hwnd);       return 0;
        }
        break;

    case WM_CTLCOLORSTATIC: {
        /* transparent label backgrounds so they sit on the window colour */
        SetBkMode((HDC)wp, TRANSPARENT);
        return (LRESULT)GetSysColorBrush(COLOR_BTNFACE);
    }

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
    wc.lpszClassName = "LYKN_KeygenMe";
    wc.hIcon         = LoadIconA(NULL, IDI_APPLICATION);
    RegisterClassExA(&wc);

    /* client area 500 x 390 -> add non-client frame */
    rc.left = 0; rc.top = 0; rc.right = 500; rc.bottom = 390;
    AdjustWindowRect(&rc, style, FALSE);
    win_w = rc.right - rc.left;
    win_h = rc.bottom - rc.top;

    hwnd = CreateWindowExA(0, "LYKN_KeygenMe",
                           "LYKNCTF 2026 :: Loi Yeu Kho Noi KeygenMe",
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
