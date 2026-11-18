#!/usr/bin/env python3
"""Test TLS 7.x handshake over TDS PRELOGIN framing, WITHOUT LOGIN7."""
import socket
import ssl
import sys

EXAMPLE = bytes.fromhex(
    "12 01 00 2f 00 00 01 00 "
    "00 00 1a 00 06 01 00 20 00 01 02 00 21 00 01 "
    "03 00 22 00 04 04 00 26 00 01 ff "
    "09 00 00 00 00 00 01 00 b8 0d 00 00 01"
)


def exact(sock, count):
    result = bytearray()
    while len(result) < count:
        buf = sock.recv(count - len(result))
        if not buf:
            raise EOFError("unexpected EOF")
        result.extend(buf)
    return bytes(result)


def recv_tds(sock, packet_type):
    out = bytearray()
    for _ in range(32):
        header = exact(sock, 8)
        if header[0] != packet_type:
            raise ValueError(f"unexpected TDS type {header[0]:#x}")
        length = int.from_bytes(header[2:4], "big")
        if not 8 <= length <= 32768:
            raise ValueError("invalid TDS length")
        out.extend(exact(sock, length - 8))
        if len(out) > 64 * 1024:
            raise ValueError("TDS payload too large")
        if header[1] & 1:
            return bytes(out)
    raise ValueError("too many TDS packets")


def send_tds(sock, packet_type, payload):
    if not payload:
        return
    chunks = [payload[i : i + 32760] for i in range(0, len(payload), 32760)]
    for i, chunk in enumerate(chunks):
        length = len(chunk) + 8
        header = bytes((packet_type, 1 if i == len(chunks) - 1 else 0))
        header += length.to_bytes(2, "big") + bytes((0, 0, i + 1, 0))
        sock.sendall(header + chunk)


def check_encryption(response):
    index = 0
    while index < len(response) and response[index] != 255:
        if index + 5 > len(response):
            raise ValueError("invalid PRELOGIN descriptor")
        kind = response[index]
        off = int.from_bytes(response[index + 1 : index + 3], "big")
        size = int.from_bytes(response[index + 3 : index + 5], "big")
        if kind == 1:
            if response[off : off + size] != b"\x03":
                raise ValueError("HADES did not require TLS")
            return
        index += 5
    raise ValueError("no ENCRYPTION option in PRELOGIN reply")


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: tls_smoke.py /path/to/hades-test.crt")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cafile=sys.argv[1])
    incoming = ssl.MemoryBIO()
    outgoing = ssl.MemoryBIO()
    tls = ctx.wrap_bio(incoming, outgoing, server_hostname="localhost")
    with socket.create_connection(("127.0.0.1", 11433), timeout=5) as sock:
        sock.settimeout(5)
        sock.sendall(EXAMPLE)
        check_encryption(recv_tds(sock, 4))
        for _ in range(32):
            finished = False
            try:
                tls.do_handshake()
                finished = True
            except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                pass
            pending = outgoing.read()
            if pending:
                send_tds(sock, 0x12, pending)
            if finished:
                print("OK: certificate-verified TDS 7.x TLS handshake; no credentials sent")
                return
            incoming.write(recv_tds(sock, 0x12))
        raise RuntimeError("TLS handshake exceeded message limit")


if __name__ == "__main__":
    main()
