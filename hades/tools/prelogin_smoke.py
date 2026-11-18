#!/usr/bin/env python3
"""Local TDS PRELOGIN smoke test. Never sends credentials."""
import socket
import sys

HOST = "127.0.0.1"
PORT = 11433

# The public MS-TDS 4.1 example: PRELOGIN packet with VERSION/ENCRYPTION/
# INSTANCE/THREADID/MARS. The frame is 47 bytes including TDS header.
REQUEST = bytes.fromhex(
    "12 01 00 2f 00 00 01 00 "
    "00 00 1a 00 06 01 00 20 00 01 "
    "02 00 21 00 01 03 00 22 00 04 "
    "04 00 26 00 01 ff "
    "09 00 00 00 00 00 01 00 b8 0d 00 00 01"
)


def read_exact(sock, count):
    result = bytearray()
    while len(result) < count:
        chunk = sock.recv(count - len(result))
        if not chunk:
            raise RuntimeError("server closed connection early")
        result.extend(chunk)
    return bytes(result)


def main():
    with socket.create_connection((HOST, PORT), timeout=5) as conn:
        conn.settimeout(5)
        conn.sendall(REQUEST)
        header = read_exact(conn, 8)
        if header[0] != 0x04 or header[1] & 1 == 0:
            raise RuntimeError(f"incorrect TDS response header: {header.hex()}")
        total = int.from_bytes(header[2:4], "big")
        if total < 9 or total > 32768:
            raise RuntimeError(f"unexpected TDS length: {total}")
        body = read_exact(conn, total - 8)
        pos = 0
        options = {}
        while True:
            token = body[pos]
            if token == 0xff:
                break
            offset = int.from_bytes(body[pos + 1:pos + 3], "big")
            length = int.from_bytes(body[pos + 3:pos + 5], "big")
            options[token] = body[offset:offset + length]
            pos += 5
        if options.get(1) != b"\x02":
            raise RuntimeError("expected ENCRYPT_NOT_SUP; TLS not yet implemented")
        print("OK: structurally correct TDS PRELOGIN response, no credentials sent")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        sys.exit(1)
