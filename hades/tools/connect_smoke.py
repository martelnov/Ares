#!/usr/bin/env python3
"""Verify that a plain TCP connect is logged before any TDS/PRELOGIN bytes.

Use only with an isolated HADES loopback listener and test evidence file.
"""
import json
import socket
import sys
import time
from pathlib import Path


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: connect_smoke.py /tmp/hades-evidence.jsonl")
    log = Path(sys.argv[1])
    before = log.stat().st_size if log.exists() else 0
    with socket.create_connection(("127.0.0.1", 11433), timeout=5) as sock:
        source_port = sock.getsockname()[1]
        deadline = time.monotonic() + 5
        # Keep TCP open and send no application data: the event must already exist.
        while True:
            if log.exists():
                with log.open("rb") as evidence:
                    evidence.seek(before)
                    raw = evidence.read()
                lines = [line for line in raw.splitlines() if line.strip()]
                if lines:
                    break
            if time.monotonic() > deadline:
                raise AssertionError("no durable event before PRELOGIN")
            time.sleep(0.05)
        assert len(lines) == 1, f"expected one CONNECT event, got {len(lines)}"
        event = json.loads(lines[0])
        assert event["event"]["action"] == "tcp_connect"
        assert event["event"]["severity"] == "critical"
        assert event["source"]["ip"] == "127.0.0.1"
        assert event["source"]["port"] == source_port
        assert event["destination"]["port"] == 11433
        assert event["session"]["id"]
        assert "authentication" not in event
    print("OK: TCP CONNECT -> durable CRITICAL JSONL before PRELOGIN")


if __name__ == "__main__":
    main()
