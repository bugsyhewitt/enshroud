"""Scope file parsing and URL validation."""
from __future__ import annotations

import ipaddress
import socket
from pathlib import Path
from urllib.parse import urlparse


def load_scope(scope_file: str) -> list[str]:
    """Parse a scope file and return a list of scope entries (hostnames, IPs, CIDRs)."""
    entries: list[str] = []
    path = Path(scope_file)
    with path.open() as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            entries.append(line)
    return entries


def _resolve_host(host: str) -> list[str]:
    """Resolve a hostname to its IP addresses. Returns empty list on failure."""
    try:
        results = socket.getaddrinfo(host, None)
        return list({r[4][0] for r in results})
    except socket.gaierror:
        return []


def _host_in_scope(host: str, scope_entries: list[str]) -> bool:
    """Check whether a host (hostname or IP) is within the scope entries."""
    host = host.lower().rstrip(".")

    for entry in scope_entries:
        entry = entry.strip().lower()
        if not entry:
            continue

        # Direct hostname match
        if host == entry:
            return True

        # Subdomain match: host ends with .entry
        if host.endswith("." + entry):
            return True

        # Try to interpret the entry as an IP or CIDR
        try:
            network = ipaddress.ip_network(entry, strict=False)
            # Try host as an IP
            try:
                addr = ipaddress.ip_address(host)
                if addr in network:
                    return True
            except ValueError:
                pass
            # Try resolving host
            resolved = _resolve_host(host)
            for ip_str in resolved:
                try:
                    if ipaddress.ip_address(ip_str) in network:
                        return True
                except ValueError:
                    pass
        except ValueError:
            pass

    return False


def target_in_scope(target_url: str, scope_entries: list[str]) -> bool:
    """Return True if the target URL's host is in scope."""
    parsed = urlparse(target_url)
    host = parsed.hostname or ""
    return _host_in_scope(host, scope_entries)


def get_target_host(target_url: str) -> str:
    """Extract the hostname from a URL."""
    parsed = urlparse(target_url)
    return parsed.hostname or target_url
