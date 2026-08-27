"""
Weighted risk scoring.

Ported from the original notebook (Cell 6 — Risk Scorer). All original
weights are unchanged. The only addition is an optional `feed_matches`
signal: if a URL in the email is found on a live phishing threat feed,
that's treated as a strong, externally-confirmed indicator.
"""

KEYWORD_WEIGHTS = {
    "urgency": 10,
    "fear": 10,
    "credential_harvesting": 15,
    "financial": 10,
}

DISPLAY_NAME_POINTS = 30
REPLY_TO_MISMATCH_POINTS = 25
PRIVATE_IP_POINTS_EACH = 15
PRIVATE_IP_POINTS_MAX = 30
FEED_MATCH_POINTS = 40  # externally-confirmed known-bad URL — strong signal
AUTH_DMARC_FAIL_POINTS = 35  # the receiving mail server itself flagged this
AUTH_SPF_FAIL_POINTS = 15
AUTH_DKIM_FAIL_POINTS = 15
NO_DMARC_RECORD_POINTS = 10  # weak signal alone — plenty of legit senders skip DMARC


def calculate_score(
    ip_analysis,
    keyword_findings,
    reply_to_mismatch,
    suspicious_display_name=None,
    feed_matches=None,
    auth_results=None,
    dmarc_lookup=None,
):
    """
    Scores the email from 0-100 based on all findings.
    Each indicator adds weighted points — higher = more suspicious.

    Weights:
      Suspicious display name : +30
      Reply-To mismatch       : +25
      Private IP in routing   : +15 each (max 30)
      Credential keywords     : +15
      Urgency keywords        : +10
      Fear keywords           : +10
      Financial keywords      : +10
      Known-bad URL (feed)    : +40
      DMARC fail (per receiving server) : +35
      SPF or DKIM fail (and DMARC didn't already fail) : +15 each
      No DMARC record published at all  : +10
    """
    score = 0
    reasons = []

    if suspicious_display_name:
        score += DISPLAY_NAME_POINTS
        reasons.append(
            f"Alarm words in sender display name: {', '.join(suspicious_display_name)} (+{DISPLAY_NAME_POINTS})"
        )

    if reply_to_mismatch:
        score += REPLY_TO_MISMATCH_POINTS
        reasons.append(f"Reply-To domain differs from sender domain (+{REPLY_TO_MISMATCH_POINTS})")

    private_ips = [r for r in ip_analysis if r["is_private"]]
    ip_points = min(len(private_ips) * PRIVATE_IP_POINTS_EACH, PRIVATE_IP_POINTS_MAX)
    if private_ips:
        score += ip_points
        reasons.append(f"{len(private_ips)} private IP(s) in routing headers (+{ip_points})")

    for category, points in KEYWORD_WEIGHTS.items():
        if category in keyword_findings:
            score += points
            count = len(keyword_findings[category])
            reasons.append(f"{count} '{category}' keyword(s) detected (+{points})")

    if feed_matches:
        score += FEED_MATCH_POINTS
        reasons.append(
            f"{len(feed_matches)} URL(s) matched a live phishing threat feed (+{FEED_MATCH_POINTS})"
        )

    if auth_results:
        if auth_results.get("dmarc") == "fail":
            score += AUTH_DMARC_FAIL_POINTS
            reasons.append(f"Receiving mail server reported DMARC fail (+{AUTH_DMARC_FAIL_POINTS})")
        else:
            # Only look at SPF/DKIM individually when DMARC itself didn't already
            # fail, so one underlying auth problem isn't counted three times.
            if auth_results.get("spf") == "fail":
                score += AUTH_SPF_FAIL_POINTS
                reasons.append(f"Receiving mail server reported SPF fail (+{AUTH_SPF_FAIL_POINTS})")
            if auth_results.get("dkim") == "fail":
                score += AUTH_DKIM_FAIL_POINTS
                reasons.append(f"Receiving mail server reported DKIM fail (+{AUTH_DKIM_FAIL_POINTS})")

    if dmarc_lookup and not dmarc_lookup.get("found") and dmarc_lookup.get("error") is None:
        # error is None means the lookup was definitive (not a timeout/network
        # issue) — the domain genuinely has no DMARC record.
        score += NO_DMARC_RECORD_POINTS
        reasons.append(f"Sender domain publishes no DMARC record (+{NO_DMARC_RECORD_POINTS})")

    return min(score, 100), reasons


def get_verdict(score: int) -> str:
    if score >= 70:
        return "🔴 HIGH RISK — Likely phishing"
    elif score >= 40:
        return "🟡 MEDIUM RISK — Suspicious, review carefully"
    elif score >= 15:
        return "🟠 LOW RISK — Some indicators present"
    else:
        return "🟢 CLEAN — No significant indicators found"
