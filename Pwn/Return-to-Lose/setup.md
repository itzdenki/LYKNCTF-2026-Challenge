# Full A-Z Setup Guide

This document explains how to build and run this challenge from scratch on
a local machine, starting from before the `dist/vuln` executable exists.

## 1. Environment Setup

### On Linux / WSL / macOS

Install the required tools:

```bash
sudo apt update
sudo apt install -y gcc python3 netcat-openbsd docker.io
```

On Windows, WSL is the most convenient way to run this.

## 2. Build the `vuln` Binary

From the challenge directory:

```bash
cd /path/to/Return-to-Lose
gcc -fno-stack-protector -no-pie -fno-pie -z noexecstack -O0 -g0 -o dist/vuln src/vuln.c
```

> Note: if gcc warns about `read` writing 256 bytes into a region of size
> 64, that's expected for this challenge — it's exactly the buffer
> overflow bug you're meant to exploit.

After building, you'll have:

```bash
./dist/vuln
```

## 3. Prepare the Flag File

Make sure `flag.txt` sits next to the binary:

```bash
cat > flag.txt <<'EOF'
LYKNCTF{ret2win_1s_s0_3asy}
EOF
```

> Note: in a real deployment, the flag should live on the server only and
> never be exposed to players.

## 4. Run the Challenge Locally

### Option 1: run the binary directly

```bash
./dist/vuln
```

If run directly, the program reads from stdin — no port needed.

### Option 2: run it through netcat / socat

If you want to expose the service over TCP like on CTFd:

```bash
socat -T60 TCP-LISTEN:9001,reuseaddr,fork EXEC:./dist/vuln,stderr
```

Then test with:

```bash
nc 127.0.0.1 9001
```

## 5. Build the Docker Image

If you want to run the challenge in a container:

```bash
docker build -t ret2win .
```

## 6. Run the Container

```bash
docker run --rm -p 9001:9001 --name ret2win ret2win
```

Then test the connection:

```bash
nc 127.0.0.1 9001
```

## 7. Run the Solver

Once the service is running, run the solver:

```bash
python3 solve.py 127.0.0.1 9001
```

On Windows you can use:

```bash
python solve.py 127.0.0.1 9001
```

Expected result:

```text
[+] Flag recovered: LYKNCTF{ret2win_1s_s0_3asy}
```

## 8. Deploying to CTFd

When uploading to CTFd, prepare the following files:

- `dist/vuln` — the executable binary
- `flag.txt` — the flag file on the server
- `Dockerfile` — if using a container
- `public/README.txt` — challenge description for players

If using Docker on CTFd, the server needs to expose the same port the
challenge listens on.

## 9. Common Troubleshooting

### Missing `dist/vuln`

If you get `No such file or directory`, rebuild the binary:

```bash
gcc -fno-stack-protector -no-pie -fno-pie -z noexecstack -O0 -g0 -o dist/vuln src/vuln.c
```

### Can't connect to the port

Check that the port is actually listening:

```bash
ss -ltnp | grep 9001
```

### Solver doesn't recover the flag

- Check that the binary has the right `win` address (`nm dist/vuln | grep -w win`)
- Check that the target is running the right service
- Check that the host/port passed to the solver are correct

## 10. Quick Recap

```bash
gcc -fno-stack-protector -no-pie -fno-pie -z noexecstack -O0 -g0 -o dist/vuln src/vuln.c
cat > flag.txt <<'EOF'
LYKNCTF{ret2win_1s_s0_3asy}
EOF
socat -T60 TCP-LISTEN:9001,reuseaddr,fork EXEC:./dist/vuln,stderr
```
