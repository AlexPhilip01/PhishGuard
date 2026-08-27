"""
The full per-email pipeline — equivalent to the notebook's `analyze_single`
(Cell 11), extended to optionally check body URLs against a live threat feed.
"""
import os

from . import ip_utils, keywords, parser, scorer, threat_feed


def analyze_single(file_path: str, feed_urls: list = None) -> dict:
    """
    Runs the full analysis pipeline on one .eml file.

    `feed_urls`: pass a list of known-bad URLs (e.g. from
    threat_feed.fetch_openphish_feed()) to also score body URLs against a
    live feed. Pass None to skip the feed check entirely (fully offline).
    """
    try:
        msg = parser.load_email(file_path)
        headers = parser.extract_headers(msg)

        reply_mismatch = parser.check_reply_to_mismatch(headers)
        suspicious_disp_name = parser.check_suspicious_display_name(headers)

        ips = ip_utils.extract_ips(headers["received"], date_header=headers["date"])
        ip_analysis = ip_utils.analyze_ips(ips)

        body = parser.extract_body(msg)
        keyword_findings = keywords.scan_subject_and_body(headers["subject"], body)

        feed_matches = None
        if feed_urls is not None:
            body_urls = threat_feed.extract_urls(body)
            feed_matches = threat_feed.check_urls_against_feed(body_urls, feed_urls)

        score, reasons = scorer.calculate_score(
            ip_analysis,
            keyword_findings,
            reply_mismatch,
            suspicious_disp_name,
            feed_matches=feed_matches,
        )
        verdict = scorer.get_verdict(score)

        return {
            "file": os.path.basename(file_path),
            "from": headers["from"],
            "subject": headers["subject"],
            "score": score,
            "verdict": verdict,
            "headers": headers,
            "ip_analysis": ip_analysis,
            "keyword_findings": keyword_findings,
            "reasons": reasons,
            "feed_matches": feed_matches,
            "error": None,
        }

    except Exception as e:
        return {
            "file": os.path.basename(file_path),
            "from": "—",
            "subject": "—",
            "score": 0,
            "verdict": "⚪ ERROR",
            "error": str(e),
        }
