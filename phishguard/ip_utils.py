"""
IP extraction and analysis from Received headers.

Ported from the original notebook (Cell 4 — IP Extractor), logic unchanged.
"""
import re

IP_PATTERN = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"

PRIVATE_RANGES = [
    "10.", "127.", "192.168.",
    "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.",
    "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
]


def is_valid_ip(ip: str) -> bool:
    """
    Validates that:
    - Each octet is between 0-255
    - First octet is not 0 (e.g. 04.x.x.x is not a real routable IP)
    - No octet has a leading zero (04 is a date fragment, not an IP octet)
    """
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        # Reject leading zeros — real IPs don't have them (04, 01, 02 etc.)
        if len(part) > 1 and part.startswith("0"):
            return False
        num = int(part)
        if not (0 <= num <= 255):
            return False
    # First octet can't be 0 — no real routable IP starts with 0
    if int(parts[0]) == 0:
        return False
    return True


def extract_ips(received_headers: list, date_header: str = "") -> list:
    """
    Pulls IPs from Received headers.
    Excludes anything that also appears in the Date header
    to avoid false positives like timestamps.
    """
    date_false_positives = re.findall(IP_PATTERN, date_header) if date_header else []

    found_ips = []
    for header in received_headers:
        for ip in re.findall(IP_PATTERN, header):
            if ip not in found_ips and is_valid_ip(ip) and ip not in date_false_positives:
                found_ips.append(ip)
    return found_ips


def is_private_ip(ip: str) -> bool:
    """
    Private IPs (192.168.x.x, 10.x.x.x etc.) shouldn't appear
    in public email routing — flags it as suspicious.
    """
    return any(ip.startswith(r) for r in PRIVATE_RANGES)


def analyze_ips(ip_list: list) -> list:
    """Returns a list of dicts with analysis for each IP."""
    results = []
    for ip in ip_list:
        private = is_private_ip(ip)
        results.append({
            "ip": ip,
            "is_private": private,
            "note": "⚠️  Private IP in routing (suspicious)" if private else "Public IP",
        })
    return results
