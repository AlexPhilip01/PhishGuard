"""
Regression tests for a false-positive found during verification: when DNS answers
NXDOMAIN for everything (hijacked/broken resolver) or the sender domain simply no
longer exists, "no DMARC record" must NOT be scored as a phishing signal.
"""
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import dns.resolver  # noqa: E402

from phishguard import dmarc, scorer  # noqa: E402


def _txt(text):
    r = MagicMock()
    r.strings = (text.encode(),)
    return r


def fake_dns(records):
    """records maps (name, rdtype) -> list of answers; anything else is NXDOMAIN."""
    def _resolve(name, rdtype, lifetime=None, **_):
        if (name, rdtype) in records:
            return records[(name, rdtype)]
        raise dns.resolver.NXDOMAIN()
    return _resolve


def lookup(records, domain="example.com"):
    with patch("dns.resolver.resolve", side_effect=fake_dns(records)):
        return dmarc.lookup_dmarc(domain)


def score_for(result):
    return scorer.calculate_score([], {}, False, [], dmarc_lookup=result)


def test_real_domain_without_dmarc_is_scored():
    r = lookup({("example.com", "NS"): [MagicMock()]})          # domain exists, no _dmarc TXT
    assert r["found"] is False and r["error"] is None and r["domain_exists"] is True
    score, reasons = score_for(r)
    assert score == 10 and any("no DMARC record" in x for x in reasons)


def test_domain_that_does_not_exist_is_not_scored():
    r = lookup({})                                               # NXDOMAIN for everything
    assert r["domain_exists"] is False
    assert score_for(r) == (0, [])


def test_hijacked_dns_answering_nxdomain_for_everything_is_not_scored():
    # Same situation from the user's side: even google.com "doesn't exist"
    r = lookup({}, domain="google.com")
    assert r["found"] is False and r["domain_exists"] is False
    assert score_for(r)[0] == 0


def test_unknown_existence_is_not_scored():
    def flaky(name, rdtype, lifetime=None, **_):
        if name.startswith("_dmarc."):
            raise dns.resolver.NXDOMAIN()
        raise dns.resolver.LifetimeTimeout()                     # can't tell if the domain exists
    with patch("dns.resolver.resolve", side_effect=flaky):
        r = dmarc.lookup_dmarc("example.com")
    assert r["domain_exists"] is None
    assert score_for(r)[0] == 0


def test_name_with_no_ns_records_still_counts_as_existing():
    def only_noanswer(name, rdtype, lifetime=None, **_):
        if name.startswith("_dmarc."):
            raise dns.resolver.NXDOMAIN()
        raise dns.resolver.NoAnswer()                            # e.g. a subdomain label
    with patch("dns.resolver.resolve", side_effect=only_noanswer):
        r = dmarc.lookup_dmarc("mail.example.com")
    assert r["domain_exists"] is True


def test_found_record_reports_domain_exists():
    r = lookup({("_dmarc.example.com", "TXT"): [_txt("v=DMARC1; p=reject")]})
    assert r["found"] is True and r["policy"] == "reject" and r["domain_exists"] is True
    assert score_for(r)[0] == 0
