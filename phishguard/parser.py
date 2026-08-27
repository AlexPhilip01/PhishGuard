"""
Header parsing for .eml files.

Ported from the original notebook (Cell 3 — Header Parser), with no change
in detection logic — only the packaging changed.
"""
import email
from email.message import Message


def load_email(file_path: str) -> Message:
    """Opens and parses a .eml file."""
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        return email.message_from_file(f)


def extract_headers(msg: Message) -> dict:
    """Extracts the key headers we care about."""
    return {
        "from": msg.get("From", "Not found"),
        "to": msg.get("To", "Not found"),
        "subject": msg.get("Subject", "Not found"),
        "reply_to": msg.get("Reply-To", "Not found"),
        "date": msg.get("Date", "Not found"),
        "received": msg.get_all("Received", []),
    }


def check_reply_to_mismatch(headers: dict) -> bool:
    """
    Checks if Reply-To domain differs from From domain.
    A classic phishing trick — attacker wants replies going somewhere else.
    """

    def get_domain(field):
        if "@" in field:
            return field.split("@")[-1].strip(">").strip().lower()
        return ""

    from_domain = get_domain(headers["from"])
    reply_domain = get_domain(headers["reply_to"])

    if from_domain and reply_domain and from_domain != reply_domain:
        return True
    return False


ALARM_WORDS = [
    "hacked", "suspended", "compromised", "urgent", "warning",
    "alert", "blocked", "locked", "virus", "infected", "action required",
]


def check_suspicious_display_name(headers: dict) -> list:
    """
    Checks if the From display name contains alarm words.
    Scammers often write 'You've been HACKED' as the display
    name to cause panic before the victim even opens the email.
    """
    from_field = headers["from"].lower()

    display_name = ""
    if "<" in from_field:
        display_name = from_field.split("<")[0].strip().strip('"')

    found = [w for w in ALARM_WORDS if w in display_name]
    return found  # empty list = no alarm words found
