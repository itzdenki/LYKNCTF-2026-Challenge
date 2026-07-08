FROM ubuntu:22.04

RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libc6-dev socat \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /usr/sbin/nologin ctf

WORKDIR /app
COPY src/vuln.c /app/vuln.c
COPY flag.txt /app/flag.txt

RUN gcc -fno-stack-protector -no-pie -fno-pie -z noexecstack -O0 -g0 -o /app/vuln /app/vuln.c \
    && rm -f /app/vuln.c \
    && chmod 0555 /app/vuln \
    && chmod 0444 /app/flag.txt \
    && chown -R root:root /app

USER ctf
EXPOSE 9001

CMD ["socat", "-T60", "TCP-LISTEN:9001,reuseaddr,fork", \
     "EXEC:/app/vuln,stderr"]
