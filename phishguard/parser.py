"""
Header parsing for .eml files.

Ported from the original notebook (Cell 3 — Header Parser), with no change
in detection logic — only the packaging changed.
"""
import email
from email.message import Message

from bs4 import BeautifulSoup


def load_email(file_path: str) -> Message:
    """Opens and parses a .eml file."""
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        return email.message_from_file(f)


def _decode_part(part) -> str:
    """Decodes one MIME part's payload to text, honoring its declared charset."""
    payload = part.get_payload(decode=True)
    if not payload:
        return ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except (LookupError, UnicodeDecodeError):
        return payload.decode("utf-8", errors="replace")


def _extract_hrefs(html: str) -> list:
    """Pulls every <a href> destination out of an HTML fragment."""
    soup = BeautifulSoup(html, "html.parser")
    return [a["href"] for a in soup.find_all("a", href=True) if a.get("href")]


def _html_to_text(html: str) -> str:
    """Converts an HTML body to plain-ish visible text for keyword scanning."""
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style"]):
        tag.decompose()
    return soup.get_text(separator=" ")


def extract_body(msg: Message) -> str:
    """
    Extracts a plain-text version of the email body — the piece the
    original notebook got wrong for multipart messages (which is most
    real-world email, since HTML + plain-text alternatives are standard).

    Main readable text prefers the text/plain part(s); if there aren't any,
    the text/html part(s) are converted to text instead. Separately, link
    destinations from ANY html part are always appended, even when a
    plain-text part was used for the main text — phishing emails often
    ship a sparse plain-text alternative with generic wording like "click
    here", while the real URL only exists in the HTML version's href, so
    relying on the plain-text part alone would silently miss it.

    Actual file attachments (Content-Disposition: attachment) are skipped —
    this is about the message body, not attachment contents.
    """
    if not msg.is_multipart():
        return _decode_part(msg)

    plain_parts, html_parts = [], []
    for part in msg.walk():
        if "attachment" in str(part.get("Content-Disposition", "")).lower():
            continue
        content_type = part.get_content_type()
        if content_type == "text/plain":
            plain_parts.append(_decode_part(part))
        elif content_type == "text/html":
            html_parts.append(_decode_part(part))

    if plain_parts:
        text = "\n".join(p for p in plain_parts if p)
    elif html_parts:
        text = "\n".join(_html_to_text(h) for h in html_parts if h)
    else:
        text = ""

    extra_links = [href for h in html_parts for href in _extract_hrefs(h)]
    if extra_links:
        text += "\n" + "\n".join(extra_links)

    return text


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
