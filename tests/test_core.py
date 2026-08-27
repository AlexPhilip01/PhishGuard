"""
Basic tests for the core detection logic. Run with:  pytest
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from phishguard import ip_utils, keywords, parser, scorer  # noqa: E402


def test_valid_ip():
    assert ip_utils.is_valid_ip("192.168.1.1") is True
    assert ip_utils.is_valid_ip("256.1.1.1") is False   # out of range
    assert ip_utils.is_valid_ip("04.1.1.1") is False    # leading zero
    assert ip_utils.is_valid_ip("0.1.1.1") is False     # first octet 0
    assert ip_utils.is_valid_ip("1.2.3") is False        # wrong shape


def test_private_ip_detection():
    assert ip_utils.is_private_ip("192.168.1.5") is True
    assert ip_utils.is_private_ip("10.0.0.1") is True
    assert ip_utils.is_private_ip("8.8.8.8") is False


def test_reply_to_mismatch():
    headers_mismatch = {"from": "Bank <bank@bank.com>", "reply_to": "attacker@gmail.com"}
    headers_match = {"from": "Bank <bank@bank.com>", "reply_to": "support@bank.com"}
    assert parser.check_reply_to_mismatch(headers_mismatch) is True
    assert parser.check_reply_to_mismatch(headers_match) is False


def test_suspicious_display_name():
    headers = {"from": '"You\'ve been HACKED" <x@example.com>'}
    found = parser.check_suspicious_display_name(headers)
    assert "hacked" in found

    headers_clean = {"from": '"Alice Johnson" <alice@example.com>'}
    assert parser.check_suspicious_display_name(headers_clean) == []


def test_keyword_scan():
    findings = keywords.scan_text("URGENT: verify your password immediately")
    assert "urgency" in findings
    assert "credential_harvesting" in findings


def test_score_and_verdict_clean_email():
    score, reasons = scorer.calculate_score(
        ip_analysis=[], keyword_findings={}, reply_to_mismatch=False, suspicious_display_name=[]
    )
    assert score == 0
    assert scorer.get_verdict(score).startswith("🟢")


def test_score_and_verdict_high_risk_email():
    ip_analysis = [{"ip": "192.168.1.1", "is_private": True, "note": "private"}]
    keyword_findings = {"urgency": ["urgent"], "credential_harvesting": ["password"]}
    score, reasons = scorer.calculate_score(
        ip_analysis=ip_analysis,
        keyword_findings=keyword_findings,
        reply_to_mismatch=True,
        suspicious_display_name=["hacked"],
    )
    # 30 (display name) + 25 (reply-to) + 15 (private ip) + 10 (urgency) + 15 (credential) = 95
    assert score == 95
    assert scorer.get_verdict(score).startswith("🔴")
    assert len(reasons) == 5


def test_feed_match_boosts_score():
    score_without, _ = scorer.calculate_score([], {}, False, [], feed_matches=None)
    score_with, reasons_with = scorer.calculate_score([], {}, False, [], feed_matches=["http://bad.example/login"])
    assert score_with == score_without + 40
    assert any("threat feed" in r for r in reasons_with)
