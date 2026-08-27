"""
Terminal report, batch summary table, and PDF export.

`print_report` and `print_summary_table` are ported unchanged from the
notebook (Cells 7 and 11).

The PDF export is upgraded: the original notebook (Cell 12) built a styled
HTML file and relied on Colab's `files.download()` plus a manual
"open in your browser, Ctrl+P, Save as PDF" step. Outside Colab there's no
browser to hand off to, so this version renders the same HTML directly to
a real .pdf file with xhtml2pdf. If xhtml2pdf isn't installed, it falls
back to writing the .html file and says so, rather than failing outright.
"""
from pathlib import Path


def print_report(headers, ip_analysis, keyword_findings, score, reasons, verdict, feed_matches=None):
    print("\n" + "=" * 55)
    print("       PHISHING EMAIL ANALYSIS REPORT")
    print("=" * 55)

    print("\n📧 EMAIL HEADERS")
    print(f"  From:     {headers['from']}")
    print(f"  To:       {headers['to']}")
    print(f"  Subject:  {headers['subject']}")
    print(f"  Date:     {headers['date']}")
    print(f"  Reply-To: {headers['reply_to']}")

    print("\n🌐 IP ADDRESSES (from Received headers)")
    if ip_analysis:
        for entry in ip_analysis:
            print(f"  {entry['ip']}  —  {entry['note']}")
    else:
        print("  No IPs found in headers")

    print("\n🔍 KEYWORD ANALYSIS")
    if keyword_findings:
        for category, words in keyword_findings.items():
            print(f"  [{category.upper()}]  →  {', '.join(words)}")
    else:
        print("  No suspicious keywords detected")

    if feed_matches is not None:
        print("\n🛰️  THREAT FEED CHECK")
        if feed_matches:
            for url in feed_matches:
                print(f"  ⚠️  {url}  —  matches a known-active phishing URL")
        else:
            print("  No URLs matched the live feed")

    print("\n📊 RISK SCORE BREAKDOWN")
    if reasons:
        for reason in reasons:
            print(f"  • {reason}")
    else:
        print("  No risk factors found")

    print("\n" + "-" * 55)
    print(f"  RISK SCORE :  {score} / 100")
    print(f"  VERDICT    :  {verdict}")
    print("=" * 55 + "\n")


def print_summary_table(results):
    """Prints a ranked summary table of all analyzed emails, highest score first."""
    sorted_results = sorted(results, key=lambda x: x["score"], reverse=True)

    print("\n" + "=" * 75)
    print("                     BATCH ANALYSIS SUMMARY")
    print("=" * 75)
    print(f"  {'FILE':<25} {'SCORE':<8} {'VERDICT'}")
    print("-" * 75)

    for r in sorted_results:
        filename = r["file"][:24]
        print(f"  {filename:<25} {r['score']:<8} {r['verdict']}")

    print("=" * 75)

    scores = [r["score"] for r in results if r.get("error") is None]
    high_risk = [r for r in results if r["score"] >= 70]

    if scores:
        print(f"\n  📁 Total emails analyzed : {len(results)}")
        print(f"  🔴 High risk emails      : {len(high_risk)}")
        print(f"  📊 Average risk score    : {sum(scores) // len(scores)} / 100")
        print(f"  📈 Highest score         : {max(scores)} / 100")
    print()


def _build_html_report(results) -> str:
    html_rows = ""
    for r in sorted(results, key=lambda x: x["score"], reverse=True):
        score = r["score"]
        if score >= 70:
            verdict_color, row_bg = "#e74c3c", "#fdf0f0"
        elif score >= 40:
            verdict_color, row_bg = "#e67e22", "#fef9f0"
        elif score >= 15:
            verdict_color, row_bg = "#f39c12", "#fffdf0"
        else:
            verdict_color, row_bg = "#27ae60", "#f0fdf4"

        all_ips = [e["ip"] for e in r.get("ip_analysis", [])]
        private_ips = [e["ip"] for e in r.get("ip_analysis", []) if e["is_private"]]
        kw = r.get("keyword_findings", {})

        urgency = ", ".join(kw.get("urgency", [])) or "None"
        fear = ", ".join(kw.get("fear", [])) or "None"
        credential = ", ".join(kw.get("credential_harvesting", [])) or "None"
        financial = ", ".join(kw.get("financial", [])) or "None"
        feed_matches = r.get("feed_matches") or []

        breakdown_html = "<ul style='margin:4px 0; padding-left:18px;'>"
        for reason in r.get("reasons", []):
            breakdown_html += f"<li>{reason}</li>"
        if not r.get("reasons"):
            breakdown_html += "<li>No risk factors found</li>"
        breakdown_html += "</ul>"

        feed_html = ""
        if feed_matches:
            feed_html = (
                "<div class='section-title'>🛰️ Threat Feed Matches</div>"
                "<ul style='margin:4px 0; padding-left:18px;'>"
                + "".join(f"<li>{u}</li>" for u in feed_matches)
                + "</ul>"
            )

        html_rows += f"""
        <div class="email-card" style="background:{row_bg};">
            <div class="card-header">
                <span class="filename">📄 {r['file']}</span>
                <span class="score-badge" style="background:{verdict_color};">
                    {score} / 100 — {r['verdict']}
                </span>
            </div>

            <table class="detail-table">
                <tr>
                    <td class="label">From</td>
                    <td>{r['headers']['from']}</td>
                    <td class="label">Date</td>
                    <td>{r['headers']['date']}</td>
                </tr>
                <tr>
                    <td class="label">Subject</td>
                    <td>{r['headers']['subject']}</td>
                    <td class="label">Reply-To</td>
                    <td>{r['headers']['reply_to']}</td>
                </tr>
                <tr>
                    <td class="label">IPs Found</td>
                    <td>{', '.join(all_ips) if all_ips else 'None'}</td>
                    <td class="label">Private IPs</td>
                    <td>{'⚠️ ' + ', '.join(private_ips) if private_ips else 'None'}</td>
                </tr>
            </table>

            <div class="section-title">🔍 Keywords Detected</div>
            <table class="detail-table">
                <tr>
                    <td class="label">Urgency</td>
                    <td>{urgency}</td>
                    <td class="label">Fear</td>
                    <td>{fear}</td>
                </tr>
                <tr>
                    <td class="label">Credential</td>
                    <td>{credential}</td>
                    <td class="label">Financial</td>
                    <td>{financial}</td>
                </tr>
            </table>
            {feed_html}
            <div class="section-title">📊 Risk Score Breakdown</div>
            {breakdown_html}
        </div>
        """

    scores = [r["score"] for r in results if r.get("error") is None]
    high_risk = [r for r in results if r["score"] >= 70]
    avg_score = sum(scores) // len(scores) if scores else 0

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>Phishing Analysis Report</title>
        <style>
            * {{ box-sizing: border-box; margin: 0; padding: 0; }}
            body {{
                font-family: 'Segoe UI', Arial, sans-serif;
                font-size: 13px;
                color: #2c3e50;
                background: #fff;
                padding: 30px;
            }}
            .report-header {{
                background: linear-gradient(135deg, #1a1a2e, #16213e);
                color: white;
                padding: 30px;
                border-radius: 10px;
                margin-bottom: 25px;
                text-align: center;
            }}
            .report-header h1 {{ font-size: 26px; letter-spacing: 1px; margin-bottom: 6px; }}
            .report-header p {{ color: #a0aec0; font-size: 13px; }}
            .summary-bar {{ display: flex; gap: 15px; margin-bottom: 25px; }}
            .stat-box {{
                flex: 1; background: #f8f9fa; border: 1px solid #e2e8f0;
                border-radius: 8px; padding: 15px; text-align: center;
            }}
            .stat-box .stat-num {{ font-size: 28px; font-weight: bold; color: #2c3e50; }}
            .stat-box .stat-label {{
                font-size: 11px; color: #718096; margin-top: 4px;
                text-transform: uppercase; letter-spacing: 0.5px;
            }}
            .email-card {{
                border: 1px solid #e2e8f0; border-radius: 8px; padding: 18px;
                margin-bottom: 18px; page-break-inside: avoid;
            }}
            .card-header {{
                display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;
            }}
            .filename {{ font-weight: bold; font-size: 14px; color: #2d3748; }}
            .score-badge {{ color: white; padding: 5px 12px; border-radius: 20px; font-size: 12px; font-weight: bold; }}
            .detail-table {{ width: 100%; border-collapse: collapse; margin-bottom: 10px; font-size: 12px; }}
            .detail-table td {{ padding: 5px 8px; border: 1px solid #e2e8f0; }}
            .label {{ background: #edf2f7; font-weight: bold; width: 12%; color: #4a5568; white-space: nowrap; }}
            .section-title {{
                font-weight: bold; font-size: 12px; color: #4a5568; margin: 10px 0 5px 0;
                text-transform: uppercase; letter-spacing: 0.5px;
            }}
            ul li {{ font-size: 12px; color: #4a5568; margin-bottom: 2px; }}
            .footer {{
                text-align: center; color: #a0aec0; font-size: 11px; margin-top: 30px;
                padding-top: 15px; border-top: 1px solid #e2e8f0;
            }}
        </style>
    </head>
    <body>
        <div class="report-header">
            <h1>🛡️ Phishing Email Analysis Report</h1>
            <p>Generated by PhishGuard</p>
        </div>
        <div class="summary-bar">
            <div class="stat-box"><div class="stat-num">{len(results)}</div><div class="stat-label">Emails Analyzed</div></div>
            <div class="stat-box"><div class="stat-num" style="color:#e74c3c;">{len(high_risk)}</div><div class="stat-label">High Risk</div></div>
            <div class="stat-box"><div class="stat-num">{avg_score}</div><div class="stat-label">Average Score</div></div>
            <div class="stat-box"><div class="stat-num">{max(scores) if scores else 0}</div><div class="stat-label">Highest Score</div></div>
        </div>
        {html_rows}
        <div class="footer">PhishGuard — For educational and research purposes only</div>
    </body>
    </html>
    """


def export_html_report(results, output_path: str) -> str:
    """Writes the styled HTML report to disk. Returns the path written."""
    html = _build_html_report(results)
    Path(output_path).write_text(html, encoding="utf-8")
    return output_path


def export_pdf_report(results, output_path: str) -> tuple:
    """
    Renders a real PDF straight to disk. Returns (path_written, format) where
    format is "pdf" on success or "html" if xhtml2pdf isn't available/fails,
    in which case an .html file is written next to the requested path instead.
    """
    html = _build_html_report(results)
    try:
        from xhtml2pdf import pisa
    except ImportError:
        html_path = str(Path(output_path).with_suffix(".html"))
        Path(html_path).write_text(html, encoding="utf-8")
        return html_path, "html"

    with open(output_path, "wb") as f:
        result = pisa.CreatePDF(html, dest=f)

    if result.err:
        html_path = str(Path(output_path).with_suffix(".html"))
        Path(html_path).write_text(html, encoding="utf-8")
        return html_path, "html"

    return output_path, "pdf"
