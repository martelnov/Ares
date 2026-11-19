#!/usr/bin/env python3
"""Loopback-only fake LOGIN7 over TDS 7.x TLS. Never use real credentials."""
import json
import socket
import ssl
import sys
from pathlib import Path

from tls_smoke import EXAMPLE, check_encryption, recv_tds, send_tds

USERNAME = "local_fake_user"
PASSWORD = "FakeTestOnly!123"


def make_login7():
    # Matches the LOGIN7 94-byte fixed header parsed by the Rust library.
    header = bytearray(94)
    header[4:8] = (0x74000004).to_bytes(4, "little")
    header[8:12] = (4096).to_bytes(4, "little")
    header[36:38] = (94).to_bytes(2, "little")
    for offset, value, is_password in [(40, USERNAME, False), (44, PASSWORD, True)]:
        buf = bytearray(value.encode("utf-16le"))
        if is_password:
            for i, b in enumerate(buf):
                masked = b ^ 0xA5
                buf[i] = ((masked << 4) | (masked >> 4)) & 0xFF
        start = len(header)
        header[offset : offset + 2] = start.to_bytes(2, "little")
        header[offset + 2 : offset + 4] = (len(buf) // 2).to_bytes(2, "little")
        header.extend(buf)
    header[0:4] = len(header).to_bytes(4, "little")
    return bytes(header)


def exact_tls(tls, inbound, sock, size):
    result = bytearray()
    while len(result) < size:
        try:
            chunk = tls.read(size - len(result))
            if not chunk:
                raise EOFError("TLS stream closed")
            result.extend(chunk)
        except ssl.SSLWantReadError:
            wire = sock.recv(32768)
            if not wire:
                raise EOFError("TLS response missing")
            inbound.write(wire)
    return bytes(result)


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: login7_smoke.py /tmp/hades-test.crt /tmp/hades-evidence.jsonl")
    log = Path(sys.argv[2])
    before = log.stat().st_size if log.exists() else 0
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cafile=sys.argv[1])
    inbound, outbound = ssl.MemoryBIO(), ssl.MemoryBIO()
    tls = ctx.wrap_bio(inbound, outbound, server_hostname="localhost")
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
            pending = outbound.read()
            if pending:
                send_tds(sock, 0x12, pending)
            if finished:
                break
            inbound.write(recv_tds(sock, 0x12))
        else:
            raise RuntimeError("TLS handshake did not complete")
        send_tds_over_tls = (
            bytes((0x10, 0x01))
            + (8 + len(make_login7())).to_bytes(2, "big")
            + bytes((0, 0, 1, 0))
            + make_login7()
        )
        tls.write(send_tds_over_tls)
        encrypted = outbound.read()
        assert encrypted, "no TLS ciphertext for LOGIN7"
        # TDS 7.x: after handshake, TLS application records go directly over TCP.
        sock.sendall(encrypted)
        header = exact_tls(tls, inbound, sock, 8)
        assert header[0] == 4, f"expected TDS response, got {header[0]:#x}"
        n = int.from_bytes(header[2:4], "big")
        response = exact_tls(tls, inbound, sock, n - 8)
        assert response[0] == 0xAA, "server did not send ERROR token"
        assert int.from_bytes(response[3:7], "little") == 18456, "not SQL error 18456"
        assert response[-13] == 0xFD, "no final DONE token"

    with log.open("rb") as fh:
        fh.seek(before)
        entries = [json.loads(line) for line in fh if line.strip()]
    assert len(entries) == 1, f"expected one new forensic event, got {len(entries)}"
    event = entries[0]
    assert event["authentication"]["username"] == USERNAME
    assert event["authentication"]["password"] == PASSWORD
    assert event["event"]["outcome"] == "failure"
    print("OK: TLS LOGIN7 -> durable JSONL with fake password -> TDS 18456 login failure")


if __name__ == "__main__":
    main()
