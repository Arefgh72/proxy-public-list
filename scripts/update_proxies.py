#!/usr/bin/env python3
"""Build a small list of public HTTP CONNECT proxies verified with TLS."""

from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import json
import socket
import ssl
import sys
import time
import urllib.request
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCES = ROOT / "sources.json"
DEFAULT_OUTPUT = ROOT / "proxies.txt"
DEFAULT_STATUS = ROOT / "status.json"
MAX_SOURCE_BYTES = 8 * 1024 * 1024
MAX_CANDIDATES = 30000
MAX_WORKERS = 100
LATENCY_LIMIT_MS = 1000
PROBE_TIMEOUT_SECONDS = 1.0
TEST_HOSTS = ("example.com", "browserleaks.com", "claude.ai")
TEST_PORT = 443


def normalize_proxy(value: str) -> str | None:
    value = value.strip()
    if not value or value.startswith("#"):
        return None
    if value.lower().startswith("http://"):
        value = value[7:]
    elif "://" in value:
        return None
    value = value.split("/", 1)[0].strip()
    if "@" in value or value.count(":") != 1:
        return None
    raw_ip, raw_port = value.rsplit(":", 1)
    try:
        ip = ipaddress.ip_address(raw_ip)
        port = int(raw_port)
    except ValueError:
        return None
    if ip.version != 4 or not ip.is_global or not 1 <= port <= 65535:
        return None
    return f"{ip}:{port}"


def parse_candidates(text: str) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for line in text.splitlines():
        candidate = normalize_proxy(line)
        if candidate and candidate not in seen:
            seen.add(candidate)
            result.append(candidate)
            if len(result) >= MAX_CANDIDATES:
                break
    return result


def fetch_source(source: dict[str, str]) -> str:
    request = urllib.request.Request(
        source["url"],
        headers={"User-Agent": "proxy-public-list-checker/1.0", "Accept": "text/plain"},
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        if response.status != 200:
            raise RuntimeError(f"HTTP {response.status}")
        data = response.read(MAX_SOURCE_BYTES + 1)
    if len(data) > MAX_SOURCE_BYTES:
        raise RuntimeError("source exceeded size limit")
    return data.decode("utf-8", errors="replace")


def probe_proxy_host(proxy: str, test_host: str, timeout: float = PROBE_TIMEOUT_SECONDS) -> int | None:
    """Return CONNECT+verified TLS latency for one host; None means unusable/too slow."""
    host, raw_port = proxy.rsplit(":", 1)
    started = time.perf_counter()
    deadline = started + timeout
    sock: socket.socket | None = None
    tls_sock: ssl.SSLSocket | None = None
    try:
        sock = socket.create_connection((host, int(raw_port)), timeout=timeout)
        sock.settimeout(max(0.05, deadline - time.perf_counter()))
        request = (
            f"CONNECT {test_host}:{TEST_PORT} HTTP/1.1\r\n"
            f"Host: {test_host}:{TEST_PORT}\r\n"
            "Proxy-Connection: close\r\n\r\n"
        ).encode("ascii")
        sock.sendall(request)
        response = bytearray()
        while b"\r\n\r\n" not in response and len(response) < 16384:
            sock.settimeout(max(0.05, deadline - time.perf_counter()))
            chunk = sock.recv(2048)
            if not chunk:
                return None
            response.extend(chunk)
        first_line = bytes(response).split(b"\r\n", 1)[0]
        fields = first_line.split()
        if len(fields) < 2 or fields[1] != b"200":
            return None
        remaining = deadline - time.perf_counter()
        if remaining <= 0:
            return None
        context = ssl.create_default_context()
        context.set_alpn_protocols(["http/1.1"])
        sock.settimeout(remaining)
        tls_sock = context.wrap_socket(sock, server_hostname=test_host)
        sock = None
        elapsed_ms = round((time.perf_counter() - started) * 1000)
        if elapsed_ms >= LATENCY_LIMIT_MS:
            return None
        return elapsed_ms
    except (OSError, ssl.SSLError, TimeoutError, ValueError):
        return None
    finally:
        if tls_sock is not None:
            tls_sock.close()
        if sock is not None:
            sock.close()


def probe_proxy(proxy: str, timeout: float = PROBE_TIMEOUT_SECONDS) -> int | None:
    """Return the slowest verified CONNECT+TLS latency across every required target."""
    latencies: list[int] = []
    for test_host in TEST_HOSTS:
        latency = probe_proxy_host(proxy, test_host, timeout)
        if latency is None:
            return None
        latencies.append(latency)
    return max(latencies)

def refresh(
    sources: list[dict[str, str]],
    output: Path = DEFAULT_OUTPUT,
    status_path: Path = DEFAULT_STATUS,
    fetcher=fetch_source,
    prober=probe_proxy,
) -> int:
    candidates: set[str] = set()
    source_errors: list[str] = []
    successful_sources = 0
    for source in sources:
        try:
            candidates.update(parse_candidates(fetcher(source)))
            successful_sources += 1
        except Exception as error:  # a source outage must not hide the other feeds
            source_errors.append(f"{source.get('name', source.get('url', 'source'))}: {error}")

    if not successful_sources:
        raise RuntimeError("All proxy sources failed: " + "; ".join(source_errors))
    ordered = sorted(candidates)[:MAX_CANDIDATES]
    results: list[tuple[str, int]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(prober, proxy): proxy for proxy in ordered}
        for future in concurrent.futures.as_completed(futures):
            latency = future.result()
            if latency is not None and 0 <= latency < LATENCY_LIMIT_MS:
                results.append((futures[future], latency))

    results.sort(key=lambda row: (row[1], row[0]))
    if not results:
        raise RuntimeError("No HTTP CONNECT proxy completed TLS in under 1000 ms; keeping the existing list")

    output.parent.mkdir(parents=True, exist_ok=True)
    content = "".join(f"{proxy}\n" for proxy, _ in results)
    output.write_text(content, encoding="utf-8", newline="\n")
    status = {
        "checked_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source_count": len(sources),
        "source_success_count": successful_sources,
        "candidate_count": len(ordered),
        "working_count": len(results),
        "latency_limit_ms": LATENCY_LIMIT_MS,
        "probe": "HTTP CONNECT + verified TLS to " + ", ".join(f"{host}:{TEST_PORT}" for host in TEST_HOSTS),
        "source_errors": source_errors,
    }
    status_path.parent.mkdir(parents=True, exist_ok=True)
    status_path.write_text(json.dumps(status, indent=2) + "\n", encoding="utf-8")
    return len(results)


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sources", type=Path, default=DEFAULT_SOURCES)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--status", type=Path, default=DEFAULT_STATUS)
    args = parser.parse_args(argv)
    sources = json.loads(args.sources.read_text(encoding="utf-8"))
    count = refresh(sources, args.output, args.status)
    print(f"Wrote {count} verified proxies to {args.output}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"proxy refresh failed: {error}", file=sys.stderr)
        raise SystemExit(1)
