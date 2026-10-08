"""
Look-alike (impersonation) domain detection.

Brand-new phishing sites are not on any threat feed yet, but they usually *look like*
a well-known brand: paypa1-secure.com, micros0ft-login.net, paypal.com.evil.xyz.
This module flags hosts that imitate a brand without being one of its real domains.

Signals (strong = very unlikely to be innocent, moderate = worth a look):

  homoglyph          strong    digit/letter swaps (paypa1, micr0soft, rn for m, vv for w)
                               or non-Latin look-alike letters (Cyrillic "а" for "a")
  typosquat          strong    one typo away from a brand name (paypall, amazom)
  brand-in-subdomain strong    brand used as a subdomain of someone else's domain
                               (paypal.com.evil.xyz, login.paypal.evil.xyz)
  brand-keyword      moderate  brand name plus extra words (secure-paypal-login.com)
  unofficial-domain  moderate  brand name on a domain it does not own (paypal.xyz)

It is a heuristic and is deliberately conservative: real brand domains (and their CDN /
mail / country domains) are allowlisted, short brand names (< 6 letters) are only matched
as whole words, and a bare brand name on a country TLD (amazon.in) is left alone.
The same data and rules are mirrored in index.html; tests/test_lookalike.py checks that
the two copies of the brand list stay identical.
"""
import re

# brand label -> registrable domains that really belong to it
BRANDS = {
    "paypal": ["paypal.com", "paypal.me", "paypalobjects.com", "paypal-community.com", "paypalcorp.com"],
    "amazon": ["amazon.com", "amazonaws.com", "amazon-adsystem.com", "media-amazon.com",
               "ssl-images-amazon.com", "amazonses.com", "amazontrust.com", "amazon.jobs",
               "amazon.science", "amazonpay.com", "a2z.com"],
    "microsoft": ["microsoft.com", "microsoftonline.com", "microsoftstore.com", "live.com",
                  "office.com", "office.net", "office365.com", "outlook.com", "sharepoint.com",
                  "windows.com", "windows.net", "azure.com", "azureedge.net", "azurewebsites.net",
                  "msn.com", "bing.com", "skype.com", "xbox.com", "onedrive.com", "msauth.net",
                  "msftauth.net", "microsoftazuread-sso.com"],
    "google": ["google.com", "gmail.com", "googlemail.com", "googleapis.com", "gstatic.com",
               "googleusercontent.com", "googletagmanager.com", "googleadservices.com",
               "googlesyndication.com", "googlevideo.com", "google-analytics.com",
               "googletagservices.com", "doubleclick.net", "youtube.com", "goo.gl", "withgoogle.com"],
    "apple": ["apple.com", "icloud.com", "icloud-content.com", "itunes.com", "mzstatic.com",
              "cdn-apple.com", "apple-dns.net", "appleid.com"],
    "netflix": ["netflix.com", "nflxext.com", "nflximg.net", "nflxvideo.net", "nflxso.net", "netflix.net"],
    "facebook": ["facebook.com", "facebookmail.com", "facebook.net", "fb.com", "fb.me", "fbcdn.net",
                 "fbsbx.com", "meta.com", "messenger.com", "workplace.com"],
    "instagram": ["instagram.com", "cdninstagram.com"],
    "whatsapp": ["whatsapp.com", "whatsapp.net"],
    "linkedin": ["linkedin.com", "licdn.com"],
    "twitter": ["twitter.com", "x.com", "t.co", "twimg.com"],
    "dropbox": ["dropbox.com", "dropboxusercontent.com", "dropboxmail.com"],
    "docusign": ["docusign.com", "docusign.net"],
    "adobe": ["adobe.com", "adobelogin.com", "adobe.io"],
    "zoom": ["zoom.us", "zoom.com", "zoomgov.com"],
    "dhl": ["dhl.com", "dhl.de", "dhl-usa.com"],
    "fedex": ["fedex.com"],
    "ups": ["ups.com"],
    "usps": ["usps.com", "usps.gov"],
    "chase": ["chase.com", "jpmorgan.com", "jpmorganchase.com"],
    "wellsfargo": ["wellsfargo.com", "wf.com"],
    "bankofamerica": ["bankofamerica.com", "bofa.com", "ml.com"],
    "citibank": ["citibank.com", "citi.com", "citigroup.com"],
    "hsbc": ["hsbc.com", "hsbc.co.uk", "hsbc.com.hk", "hsbc.co.in"],
    "barclays": ["barclays.com", "barclays.co.uk", "barclaycard.co.uk"],
    "hdfcbank": ["hdfcbank.com", "hdfc.com"],
    "icicibank": ["icicibank.com"],
    "axisbank": ["axisbank.com"],
    "onlinesbi": ["onlinesbi.sbi", "sbi.co.in", "sbicard.com", "onlinesbi.com"],
    "paytm": ["paytm.com", "paytmbank.com"],
    "phonepe": ["phonepe.com"],
    "coinbase": ["coinbase.com", "coinbasecloud.net"],
    "binance": ["binance.com", "binance.us"],
    "metamask": ["metamask.io"],
    "steam": ["steampowered.com", "steamcommunity.com", "steamstatic.com", "valvesoftware.com"],
    "ebay": ["ebay.com", "ebaystatic.com", "ebayimg.com"],
    "walmart": ["walmart.com", "walmartimages.com"],
    "irs": ["irs.gov"],
    "stripe": ["stripe.com", "stripe.network", "stripecdn.com"],
    "github": ["github.com", "githubusercontent.com", "githubassets.com", "githubstatus.com"],
    "slack": ["slack.com", "slack-edge.com"],
}

# Extra spellings that map onto a brand's domains (a "outlook-" site imitates Microsoft).
ALIASES = {
    "outlook": "microsoft", "office365": "microsoft", "onedrive": "microsoft",
    "sharepoint": "microsoft", "hdfc": "hdfcbank", "sbi": "onlinesbi", "gmail": "google",
    "icloud": "apple", "appleid": "apple",
}

# Real, unrelated domains that sit one typo away from a brand.
KNOWN_LEGIT_NEARBY = {"paypay.ne.jp", "paypay.co.jp", "applet.com", "zooms.com"}

MIN_SUBSTRING_LEN = 6   # shorter brand names only match as whole hyphen-separated words
MIN_SUBDOMAIN_LEN = 5   # shorter names (ups, dhl, ebay) are too common as subdomain labels
NO_TYPO_CHECK = {"stripe"}  # too close to ordinary words (strive, stripe -> strife)
MIN_TYPO_LEN = 6        # typo-squat check needs a reasonably long name to avoid noise

_SECOND_LEVEL = {"co", "com", "net", "org", "gov", "edu", "ac", "or", "ne", "go"}
_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_PLATFORM_SUFFIXES = (
    "sites.google.com", "github.io", "gitlab.io", "pages.dev", "workers.dev", "netlify.app",
    "vercel.app", "web.app", "firebaseapp.com", "herokuapp.com", "onrender.com", "weebly.com",
    "wixsite.com", "blogspot.com", "wordpress.com", "webflow.io", "glitch.me", "r2.dev",
    "ipfs.io", "dweb.link", "amazonaws.com", "azurewebsites.net", "cloudfront.net",
)

# Non-Latin letters that look like Latin ones (Cyrillic and Greek).
CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i", "ј": "j",
    "ѕ": "s", "ԁ": "d", "һ": "h", "ɡ": "g", "ο": "o", "α": "a", "ι": "i", "κ": "k", "ν": "v",
    "ρ": "p", "τ": "t", "ɑ": "a", "ӏ": "l", "ꞓ": "c",
}

STRONG_KINDS = ("homoglyph", "typosquat", "brand-in-subdomain")


def _owner(brand: str) -> str:
    return ALIASES.get(brand, brand)


def _legit_domains() -> set:
    return {d for ds in BRANDS.values() for d in ds}


def _brand_labels() -> dict:
    """Every label we watch for -> the brand that owns it."""
    out = {b: b for b in BRANDS}
    out.update({a: _owner(a) for a in ALIASES})
    return out


def _decode_host(host: str) -> str:
    """Turns xn-- labels into real Unicode so confusable letters can be seen."""
    out = []
    for label in host.split("."):
        if label.startswith("xn--"):
            try:
                label = label.encode("ascii").decode("idna")
            except Exception:
                pass
        out.append(label)
    return ".".join(out)


def _skeleton(text: str) -> str:
    return "".join(CONFUSABLES.get(c, c) for c in text)


def _homoglyph_variants(label: str) -> set:
    """Plausible 'plain' readings of a label written with look-alike characters."""
    base = []
    for one in ("l", "i"):
        s = label.replace("1", one).replace("0", "o").replace("3", "e").replace("5", "s")
        base.append(s)
    out = set(base)
    for s in base:
        out.add(s.replace("rn", "m").replace("vv", "w"))
    out.discard(label)
    return out


def _within_one_edit(a: str, b: str) -> bool:
    """True if a and b differ by exactly one insertion, deletion, substitution or swap."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        diffs = [i for i in range(len(a)) if a[i] != b[i]]
        if len(diffs) == 1:
            return True
        return len(diffs) == 2 and diffs[1] == diffs[0] + 1 and a[diffs[0]] == b[diffs[1]] and a[diffs[1]] == b[diffs[0]]
    short, long_ = (a, b) if len(a) < len(b) else (b, a)
    i = 0
    while i < len(short) and short[i] == long_[i]:
        i += 1
    return short[i:] == long_[i + 1:]


def _registrable(host: str):
    """(registrable_domain, subdomain_labels). IPs and one-label hosts return themselves."""
    labels = host.split(".")
    if len(labels) < 2:
        return host, []
    keep = 3 if (len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in _SECOND_LEVEL) else 2
    keep = min(keep, len(labels))
    return ".".join(labels[-keep:]), labels[:-keep]


def _platform_suffix(host: str):
    for s in _PLATFORM_SUFFIXES:
        if host == s or host.endswith("." + s):
            return s
    return None


def _is_legit(host: str) -> bool:
    return any(host == d or host.endswith("." + d) for d in _legit_domains())


def _hit(host, brand, kind, detail):
    return {
        "host": host,
        "brand": brand,
        "legit_domain": BRANDS[brand][0],
        "kind": kind,
        "strength": "strong" if kind in STRONG_KINDS else "moderate",
        "detail": detail,
    }


def _label_findings(host, label, labels_map):
    """Checks one registrable-domain label (or platform tenant label). Returns a hit or None."""
    tokens = [t for t in label.split("-") if t]
    variants = _homoglyph_variants(label)
    token_variants = {t: _homoglyph_variants(t) for t in tokens}

    # 1. homoglyphs (leet / look-alike letters): strongest signal
    for name, owner in labels_map.items():
        if name in label and len(name) >= MIN_SUBSTRING_LEN:
            continue  # already contains the real word; handled below
        for v in variants:
            if (name in v and len(name) >= MIN_SUBSTRING_LEN) or v == name:
                return _hit(host, owner, "homoglyph", f'"{label}" imitates "{name}" with look-alike characters')
        for tok, vs in token_variants.items():
            if name in vs:
                return _hit(host, owner, "homoglyph", f'"{tok}" imitates "{name}" with look-alike characters')

    # 2. typo-squats of a brand name
    for name, owner in labels_map.items():
        if len(name) < MIN_TYPO_LEN or name in NO_TYPO_CHECK:
            continue
        for tok in tokens:
            if len(tok) >= MIN_TYPO_LEN and tok[0] == name[0] and _within_one_edit(tok, name):
                return _hit(host, owner, "typosquat", f'"{tok}" is one character away from "{name}"')

    # 3. the brand name itself on a domain that is not theirs
    for name, owner in labels_map.items():
        if label == name:
            return _hit(host, owner, "unofficial-domain", f'uses the "{name}" name but is not their domain')
        if name in tokens:
            return _hit(host, owner, "brand-keyword", f'combines "{name}" with other words')
        if len(name) >= MIN_SUBSTRING_LEN and name in label:
            return _hit(host, owner, "brand-keyword", f'contains "{name}" inside a different domain name')
    return None


def check_host(host: str):
    """
    Returns a hit dict ({host, brand, legit_domain, kind, strength, detail}) if `host` looks
    like it imitates a well-known brand, otherwise None. Never raises.
    """
    try:
        host = (host or "").strip().lower().rstrip(".")
        if not host or _IPV4.match(host) or "." not in host:
            return None
        decoded = _decode_host(host)
        if _is_legit(host):
            return None
        reg_ascii, _ = _registrable(host)
        if reg_ascii in KNOWN_LEGIT_NEARBY or reg_ascii in _legit_domains():
            return None

        labels_map = _brand_labels()
        reg, subs = _registrable(decoded)
        plat = _platform_suffix(host)

        # Non-Latin look-alike letters anywhere in the name
        skel = _skeleton(decoded)
        if skel != decoded:
            for name, owner in labels_map.items():
                if name in skel.replace("-", ""):
                    return _hit(host, owner, "homoglyph", f'"{decoded}" uses look-alike non-Latin letters to imitate "{name}"')

        # Brand used as a subdomain / path-like label of someone else's domain
        sub_text = subs if not plat else decoded[: -len(plat)].rstrip(".").split(".")
        for lab in sub_text:
            for name, owner in labels_map.items():
                toks = lab.split("-")
                if len(name) >= MIN_SUBSTRING_LEN:
                    named = name in lab
                else:
                    named = len(name) >= MIN_SUBDOMAIN_LEN and (lab == name or name in toks)
                if named:
                    return _hit(host, owner, "brand-in-subdomain",
                                f'"{name}" appears as part of someone else\'s domain ({reg_ascii if not plat else plat})')

        if plat:
            return None  # tenant names on shared platforms are covered by the subdomain rule

        label = reg.split(".")[0]
        tld = reg.split(".")[-1]
        hit = _label_findings(host, label, labels_map)
        if hit and hit["kind"] == "unofficial-domain" and len(tld) == 2:
            return None  # amazon.in, google.co.uk and friends: country domains are usually real
        return hit
    except Exception:
        return None


def check_hosts(hosts):
    """check_host() over many hosts; returns hits, one per distinct host."""
    seen, hits = set(), []
    for h in hosts:
        h = (h or "").strip().lower().rstrip(".")
        if h in seen:
            continue
        seen.add(h)
        hit = check_host(h)
        if hit:
            hits.append(hit)
    return hits


def host_of(url_or_host: str) -> str:
    """Host part of a URL or a bare 'user@host' / 'host' string."""
    s = (url_or_host or "").strip()
    s = re.sub(r"^[a-z][a-z0-9+.-]*://", "", s, flags=re.I)
    s = re.split(r"[/?#]", s, maxsplit=1)[0]
    s = s.rsplit("@", 1)[-1]
    s = re.sub(r":\d*$", "", s)
    return s.lower().rstrip(".")
