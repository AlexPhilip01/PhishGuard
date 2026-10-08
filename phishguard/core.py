"""
The full per-email pipeline — equivalent to the notebook's `analyze_single`
(Cell 11), extended to optionally check body URLs against a live threat feed.
"""
import os

from . import dmarc, ip_utils, keywords, parser, scorer, threat_feed


def analyze_single(file_path: str, feed=None, check_dmarc: bool = True, feed_urls: list = None) -> dict:
    """
    Runs the full analysis pipeline on one .eml file.

    `feed`: a threat_feed.FeedIndex (from threat_feed.build_index()) to also
    check body URLs against live phishing feeds. Pass None to skip the feed
    check entirely (fully offline). A plain list of known-bad URLs is also
    accepted. (`feed_urls` is the older name for that list and still works.)

    `check_dmarc`: whether to run a live DNS lookup of the sender domain's
    DMARC record. Parsing any Authentication-Results header already in the
    email happens either way — that part needs no network.
    """
    if feed is None and feed_urls is not None:
        feed = feed_urls
    if isinstance(feed, (list, tuple, set)):
        index = threat_feed.FeedIndex()
        index.add_urls("list", feed)
        feed = index

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
        feed_match_details = None
        if feed is not None:
            body_urls = threat_feed.extract_urls(body)
            feed_match_details = feed.match_all(body_urls)
            feed_matches = [m["url"] for m in feed_match_details]

        auth_results = dmarc.parse_authentication_results(headers)
        dmarc_lookup = None
        if check_dmarc:
            sender_domain = dmarc.get_domain(headers["from"])
            dmarc_lookup = dmarc.lookup_dmarc(sender_domain)

        score, reasons = scorer.calculate_score(
            ip_analysis,
            keyword_findings,
            reply_mismatch,
            suspicious_disp_name,
            feed_matches=feed_matches,
            auth_results=auth_results,
            dmarc_lookup=dmarc_lookup,
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
            "feed_match_details": feed_match_details,
            "auth_results": auth_results,
            "dmarc_lookup": dmarc_lookup,
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
