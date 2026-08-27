"""
Categorized phishing keyword detection.

Ported from the original notebook (Cell 5 — Keyword Detector), logic unchanged.
"""

KEYWORD_CATEGORIES = {
    "urgency": [
        "urgent", "immediately", "action required", "act now",
        "expires", "suspended", "24 hours", "last chance", "final notice",
    ],
    "fear": [
        "compromised", "unauthorized", "suspicious activity",
        "hacked", "breach", "locked", "disabled", "terminated",
    ],
    "credential_harvesting": [
        "verify", "confirm", "validate", "update your",
        "re-enter", "login", "sign in", "password", "credentials",
    ],
    "financial": [
        "bank account", "credit card", "payment", "billing",
        "invoice", "refund", "transaction", "wire transfer",
    ],
}


def get_keyword_list() -> dict:
    """Categorized phishing keywords."""
    return KEYWORD_CATEGORIES


def scan_text(text: str) -> dict:
    """Scans text and returns matched keywords grouped by category."""
    text_lower = text.lower()
    findings = {}
    for category, kws in get_keyword_list().items():
        matched = [kw for kw in kws if kw in text_lower]
        if matched:
            findings[category] = matched
    return findings


def scan_subject_and_body(subject: str, body: str = "") -> dict:
    return scan_text(subject + " " + body)
