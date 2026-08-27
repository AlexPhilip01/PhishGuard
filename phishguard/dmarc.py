"""
DMARC/SPF domain authentication checks — new in this version.

Two complementary signals, combined:

1. Parsing any Authentication-Results header already in the email. When
   present, this reflects what the RECEIVING mail server (Gmail, Outlook,
   a corporate gateway, etc.) already verified at delivery time — it's more
   authoritative than anything re-derivable after the fact, because it
   reflects the actual SMTP session, not just a snapshot of DNS today.

2. A live DNS lookup of the sender domain's _dmarc.<domain> TXT record, to
   see what policy is currently published. Useful on its own (no header
   needed), and as a sanity check alongside #1.

Like the threat-feed check, DNS lookups fail *safely*: no resolver, no
network, a timeout, an NXDOMAIN — none of it should crash an analysis.
A genuine "this domain has no DMARC record" is treated as a real (if weak)
signal; an inconclusive lookup (timeout, no network) is not scored at all,
since we don't actually know the answer in that case.
"""
import re
from email.utils import parseaddr

AUTH_RESULT_PATTERN = re.compile(r"\b(spf|dkim|dmarc)=(\w+)", re.IGNORECASE)


def get_domain(email_address: str) -> str:
    """Extracts the domain from an address like 'Name <user@domain.com>'."""
    _, addr = parseaddr(email_address or "")
    if "@" in addr:
        return addr.split("@")[-1].lower()
    return ""


def parse_authentication_results(headers: dict) -> dict:
    """
    Extracts spf/dkim/dmarc verdicts from Authentication-Results header(s)
    added by the receiving mail server, e.g. {"spf": "pass", "dkim": "pass",
    "dmarc": "pass"}. Only keys actually found are included. If the header
    appears more than once (one per hop), the first — closest to final
    delivery — instance wins for each key.
    """
    raw = headers.get("authentication_results")
    if not raw:
        return {}
    if isinstance(raw, list):
        raw = " ".join(raw)

    results = {}
    for match in AUTH_RESULT_PATTERN.finditer(raw):
        key, value = match.group(1).lower(), match.group(2).lower()
        results.setdefault(key, value)
    return results


def _txt_to_str(rdata) -> str:
    if hasattr(rdata, "strings"):  # modern dnspython TXT rdata: tuple of byte chunks
        return b"".join(rdata.strings).decode("utf-8", errors="replace")
    return str(rdata).strip('"')


def _parse_dmarc_tags(record: str) -> dict:
    tags = {}
    for part in record.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    return tags


def lookup_dmarc(domain: str, timeout: float = 5.0) -> dict:
    """
    Looks up _dmarc.<domain>. Returns:
      found  - True if a v=DMARC1 record exists
      policy - the "p=" value (none / quarantine / reject) if found
      raw    - the raw record text if found
      tags   - all parsed tag=value pairs if found
      error  - None on a definitive answer (found or genuinely absent);
               a description string if the lookup was inconclusive
               (timeout, no network, resolver missing)
    Never raises.
    """
    empty = {"found": False, "policy": None, "raw": None, "tags": {}}
    if not domain:
        return {**empty, "error": "no domain given"}

    try:
        import dns.resolver
    except ImportError:
        return {**empty, "error": "dnspython not installed"}

    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=timeout)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return {**empty, "error": None}  # definitive: no DMARC record published
    except Exception as e:
        return {**empty, "error": f"{type(e).__name__}: {e}"}  # inconclusive

    for rdata in answers:
        txt = _txt_to_str(rdata)
        if txt.lower().startswith("v=dmarc1"):
            tags = _parse_dmarc_tags(txt)
            return {"found": True, "policy": tags.get("p"), "raw": txt, "tags": tags, "error": None}

    return {**empty, "error": None}  # record type exists but wasn't a DMARC record
