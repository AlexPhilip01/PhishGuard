Phishing Email Analyzer

A Python-based tool that analyzes `.eml` email files to detect 
phishing indicators, calculate a risk score, and generate reports.

Runs two ways:
- **As a CLI / Python package** (`phishguard/`) — for local use, automation, or integrating into something bigger
- **As the original notebook** (`phishing_email_analyzer_Public_Code.ipynb`) — still here for a no-install-needed walkthrough in Google Colab

---

Features

- **Header Analysis** — extracts From, To, Subject, Reply-To, Date
- **IP Extraction** — pulls IPs from Received headers with false positive filtering
- **Display Name Detection** — flags alarm words like "HACKED" or "SUSPENDED"
- **Reply-To Mismatch** — detects when reply domain differs from sender domain
- **Keyword Detection** — 4 categories: urgency, fear, credential harvesting, financial. Reads both plain-text and HTML email bodies (including link URLs hidden behind text like "Click here"), not just plain-text
- **Weighted Risk Scoring** — scores emails 0–100 with a clear verdict
- **Batch Mode** — analyze multiple .eml files at once with a summary table
- **PDF Export** — generates a styled, real PDF investigation report (no manual "print to PDF" step)
- **Persistent History** — every analysis is logged locally (SQLite), so the tool builds its own record of senders/domains seen before, with `phishguard history` and `phishguard stats`
- **Live Threat Feeds** — checks URLs in the email body against continuously-updated public phishing feeds: [Phishing.Database](https://github.com/Phishing-Database/Phishing.Database) (~390k active phishing domains) and the OpenPhish community feed. Feeds are cached locally and refreshed automatically when stale, so every run uses current data. Matching is deliberately conservative: shared platforms (Google Sites, GitHub Pages, IPFS gateways, S3 endpoints…) are never flagged wholesale — only specifically-listed hosts or URLs are.
- **Live feed on the website** — a scheduled GitHub Action (`.github/workflows/update-feeds.yml`, every 6 hours) publishes a ~2 MB fingerprint snapshot of the Phishing.Database list to a `feed-data` branch. The website downloads it in the background and flags links on the list (+40 risk) in both Email and SMS modes, using the same conservative matching rules as the CLI. Only fingerprints are shipped, not the list, and if the snapshot can't be loaded the site's other checks still work. Run `phishguard build-snapshot --out feeds` to build one yourself.
- **DMARC / SPF / DKIM Check** — reads any `Authentication-Results` header the receiving mail server already added, and independently looks up the sender domain's live DMARC policy via DNS. Also works standalone for any domain: `phishguard check-domain <domain>`

---

Risk Scoring

| Indicator                  | Points |
|----------------------------|--------|
| Alarm words in display name | +30   |
| Reply-To mismatch           | +25   |
| Private IP in routing       | +15   |
| Credential keywords         | +15   |
| Urgency / Fear / Financial  | +10   |

| Score     | Verdict                          |
|-----------|----------------------------------|
| 70 – 100  | 🔴 HIGH RISK — Likely phishing   |
| 40 – 69   | 🟡 MEDIUM RISK — Suspicious      |
| 15 – 39   | 🟠 LOW RISK — Some indicators    |
| 0  – 14   | 🟢 CLEAN                         |

---

How to Run — CLI (recommended)

```bash
pip install -r requirements.txt
pip install -e .          # installs the `phishguard` command

phishguard analyze suspicious.eml                    # analyze one email
phishguard analyze suspicious.eml --pdf report.pdf   # ...and export a PDF
phishguard batch ./emails --pdf batch_report.pdf     # analyze a whole folder
phishguard batch ./emails --no-feed                  # skip the live threat-feed check
phishguard analyze suspicious.eml --feeds phishing-database   # use only one feed
phishguard update-feeds                              # refresh the live feeds right now
phishguard build-snapshot --out feeds                # compact snapshot for the website (used by the scheduled workflow)

phishguard history          # see everything analyzed so far
phishguard stats            # all-time aggregate stats

phishguard check-domain paypal.com    # check any domain's DMARC policy, standalone
```

Every analysis — CLI or batch — is automatically recorded to a local SQLite database (`~/.phishguard/phishguard.db`), so `history` and `stats` build up over time without any extra setup. Add `--no-feed` and/or `--no-dmarc` to `analyze`/`batch` to skip the network-dependent checks. Threat feeds are cached in `~/.phishguard/feeds/` and re-downloaded automatically once they are older than 6 hours (Phishing.Database) or 12 hours (OpenPhish); use `--refresh-feeds` to force it. If a feed can't be reached, the last cached copy is used, and if there is none that feed is skipped — an analysis never fails because a feed is down.

How to Run — Google Colab (original notebook)

1. Open the notebook in [Google Colab](https://colab.research.google.com)
2. Run cells 1–9 top to bottom to load all functions
3. Upload your `.eml` file(s) when prompted
4. View the full analysis report in the output
5. Run Cell 12 to export a PDF report

---

Package Structure (CLI version)

| File | Purpose |
|------|---------|
| `phishguard/parser.py` | Header parsing, reply-to mismatch, display-name checks |
| `phishguard/ip_utils.py` | IP extraction + validation from Received headers |
| `phishguard/keywords.py` | Categorized phishing keyword detection |
| `phishguard/scorer.py` | Weighted risk scoring + verdict |
| `phishguard/threat_feed.py` | Live multi-feed check (Phishing.Database + OpenPhish): cached downloads, ETag refresh, conservative matching |
| `phishguard/dmarc.py` | Authentication-Results parsing + live DMARC DNS lookup |
| `phishguard/database.py` | Persistent local history (SQLite) |
| `phishguard/report.py` | Terminal report, summary table, PDF export |
| `phishguard/core.py` | Wires the above into one per-email pipeline |
| `phishguard/cli.py` | Command-line entry point (`analyze`, `batch`, `history`, `stats`) |
| `tests/test_core.py` | Unit tests for the detection logic |
| `phishguard/snapshot.py` | Builds the compact browser snapshot (hashed host fingerprints + matching rules) |
| `tests/test_snapshot.py` | Tests for the snapshot builder, including refusal to publish an empty or stale snapshot |
| `tests/test_feeds.py` | Tests for feed matching, shared-platform protection, caching and offline behaviour (no network needed) |

> **Feed licensing:** the OpenPhish community feed is for non-commercial use only ([terms](https://openphish.com/terms.html)) — if you build PhishGuard into a commercial product, use `--feeds phishing-database` or buy an OpenPhish commercial licence. Phishing.Database is community-maintained; check its repository's LICENSE before commercial use.

Notebook Structure (original, still included)

| Cell | Purpose |
|------|---------|
| 1    | Install dependencies |
| 2    | Create sample .eml file |
| 3    | Header parser |
| 4    | IP extractor |
| 5    | Keyword detector |
| 6    | Risk scorer |
| 7    | Report printer |
| 8    | Single file analyzer |
| 9    | Upload your own .eml |
| 10   | Upload multiple .eml files |
| 11   | Batch analyzer + summary table |
| 12   | Export report to PDF |

---

Terminal Report
PHISHING EMAIL ANALYSIS REPORT
📧 From:     "You've been HACKED" kfixc@kawachi.zaq.ne.jp
Subject:  Information about your online security
🌐 IP ADDRESSES
222.227.81.164  —  Public IP
🔍 KEYWORDS
[FEAR]     →  hacked
[URGENCY]  →  immediately
[FINANCIAL]→  payment
📊 RISK SCORE :  60 / 100
VERDICT    :  🟡 MEDIUM RISK — Suspicious, review carefully

PDF Report
![Sample PDF Report](output.png)



