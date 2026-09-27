# Proxy Public List

This repository builds a fresh list of public HTTP CONNECT proxies every three hours. The output consumed is [`proxies.txt`](proxies.txt), with one `IP:PORT` per line.

The GitHub Actions workflow gathers candidates from the feeds in [`sources.json`](sources.json), removes invalid and non-public addresses, and tests each remaining proxy by opening an HTTP CONNECT tunnel and completing a certificate-verified TLS handshake with `example.com:443`. Only results below 1000 ms are written. If all sources fail or no proxy passes, the workflow fails and preserves the previous `proxies.txt`.

The scheduled run uses GitHub Actions UTC cron `0 */3 * * *`. A manual run is available from **Actions → Refresh verified proxy list → Run workflow**. The first run also starts automatically after changes are pushed to `main`.

The measured latency is the slowest of the three proxy TCP connection, CONNECT, and TLS handshakes; it is not an ICMP ping and does not guarantee that a proxy will remain online or allow every destination. Public proxies are untrusted third-party services. Do not send them credentials or sensitive traffic.
Created with AI (luna 6)
