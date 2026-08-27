"""
Basic tests for the core detection logic. Run with:  pytest
"""
import sys
from email.message import EmailMessage
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from phishguard import ip_utils, keywords, parser, scorer, threat_feed  # noqa: E402


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


# --- Body extraction: the multipart/HTML fix ---------------------------

def test_extract_body_simple_plain_text():
    msg = EmailMessage()
    msg["Subject"] = "test"
    msg.set_content("please verify your password now")
    assert "verify your password" in parser.extract_body(msg)


def test_extract_body_multipart_prefers_plain_text():
    """The exact bug that used to make body scanning silently do nothing."""
    msg = EmailMessage()
    msg["Subject"] = "test"
    msg.set_content("plain text: please confirm your credentials")
    msg.add_alternative(
        "<html><body><p>html: please <b>confirm</b> your credentials</p></body></html>",
        subtype="html",
    )
    assert msg.is_multipart()  # sanity check this is actually the multipart case
    body = parser.extract_body(msg)
    assert "confirm your credentials" in body


def test_extract_body_html_only_falls_back_and_keeps_link_urls():
    msg = EmailMessage()
    msg["Subject"] = "test"
    msg.set_content(
        "<html><body><p>Your account is locked.</p>"
        '<a href="http://paypa1-security.com/login">Click here</a>'
        "</body></html>",
        subtype="html",
    )
    body = parser.extract_body(msg)
    assert "locked" in body
    # the href itself must survive even though the visible link text doesn't mention it
    assert "http://paypa1-security.com/login" in body


def test_multipart_email_keywords_and_feed_url_are_now_detected():
    """End-to-end: a realistic multipart phishing email should now be
    fully scanned, not just its subject line."""
    msg = EmailMessage()
    msg["Subject"] = "Please review"
    msg["From"] = "Alerts <alerts@example.com>"
    msg.set_content("Your account has been compromised, verify your credentials now.")
    msg.add_alternative(
        '<html><body><p>Your account has been compromised.</p>'
        '<a href="http://paypa1-security.com/login">Verify now</a></body></html>',
        subtype="html",
    )

    body = parser.extract_body(msg)
    findings = keywords.scan_subject_and_body(msg["Subject"], body)
    assert "fear" in findings          # "compromised" — only in the body, not the subject
    assert "credential_harvesting" in findings

    urls = threat_feed.extract_urls(body)
    matches = threat_feed.check_urls_against_feed(urls, ["http://paypa1-security.com/login"])
    assert matches == ["http://paypa1-security.com/login"]
