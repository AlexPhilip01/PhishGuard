"""
Command-line entry point for PhishGuard.

This replaces the Colab-specific parts of the old notebook (Cells 1, 2, 8, 9,
10, 12 — installing deps, the file-upload widgets, and files.download()).
Everything else (parsing, scoring, reporting logic) is unchanged; this is
just how you now invoke it, from a terminal instead of clicking through
notebook cells.

Examples:
    phishguard analyze suspicious.eml
    phishguard analyze suspicious.eml --pdf report.pdf
    phishguard batch ./emails --pdf batch_report.pdf
    phishguard batch ./emails --no-feed        # skip the live threat-feed check
    phishguard history --limit 20
    phishguard stats
"""
import argparse
import glob
import os
import sys

from . import database, dmarc, report, threat_feed
from .core import analyze_single


def _get_feed_urls(use_feed: bool):
    if not use_feed:
        return None
    urls, status = threat_feed.fetch_openphish_feed()
    if status == "offline":
        print("⚠️  Could not reach the OpenPhish feed and no local cache exists — "
              "continuing without the live feed check.", file=sys.stderr)
        return None
    if status == "stale":
        print("⚠️  Could not refresh the OpenPhish feed — using a cached (possibly "
              "outdated) copy.", file=sys.stderr)
    return urls


def cmd_analyze(args):
    feed_urls = _get_feed_urls(not args.no_feed)
    result = analyze_single(args.file, feed_urls=feed_urls, check_dmarc=not args.no_dmarc)

    if result["error"]:
        print(f"❌ Error reading file: {result['error']}")
        sys.exit(1)

    report.print_report(
        result["headers"], result["ip_analysis"], result["keyword_findings"],
        result["score"], result["reasons"], result["verdict"],
        feed_matches=result["feed_matches"],
        auth_results=result["auth_results"], dmarc_lookup=result["dmarc_lookup"],
    )
    database.save_analysis(result)

    if args.pdf:
        path, fmt = report.export_pdf_report([result], args.pdf)
        if fmt == "pdf":
            print(f"📥 PDF report saved to {path}")
        else:
            print(f"📥 Report saved to {path} (install xhtml2pdf for a real .pdf)")


def cmd_batch(args):
    eml_files = sorted(glob.glob(os.path.join(args.folder, "*.eml")))
    if not eml_files:
        print(f"⚠️  No .eml files found in {args.folder}")
        return

    feed_urls = _get_feed_urls(not args.no_feed)
    print(f"🔍 Found {len(eml_files)} email(s) — analyzing...\n")

    all_results = []
    for file_path in eml_files:
        print("─" * 55)
        print(f"  Analyzing: {os.path.basename(file_path)}")
        print("─" * 55)

        result = analyze_single(file_path, feed_urls=feed_urls, check_dmarc=not args.no_dmarc)
        all_results.append(result)

        if result["error"]:
            print(f"  ❌ Error reading file: {result['error']}\n")
            continue

        report.print_report(
            result["headers"], result["ip_analysis"], result["keyword_findings"],
            result["score"], result["reasons"], result["verdict"],
            feed_matches=result["feed_matches"],
            auth_results=result["auth_results"], dmarc_lookup=result["dmarc_lookup"],
        )
        database.save_analysis(result)

    report.print_summary_table(all_results)

    if args.pdf:
        clean_results = [r for r in all_results if r["error"] is None]
        path, fmt = report.export_pdf_report(clean_results, args.pdf)
        if fmt == "pdf":
            print(f"📥 PDF report saved to {path}")
        else:
            print(f"📥 Report saved to {path} (install xhtml2pdf for a real .pdf)")


def cmd_check_domain(args):
    """Standalone DMARC (+ auth header context) check for any domain — not
    tied to analyzing a specific email."""
    domain = args.domain.strip().lower().removeprefix("http://").removeprefix("https://").rstrip("/")
    print(f"\n🔐 DMARC check — {domain}")
    print("-" * 55)

    result = dmarc.lookup_dmarc(domain, timeout=args.timeout)
    if result["found"]:
        print(f"  ✅ DMARC record found")
        print(f"     Policy (p=)      : {result['policy']}")
        for tag in ("sp", "pct", "rua", "ruf", "adkim", "aspf"):
            if tag in result["tags"]:
                print(f"     {tag:17}: {result['tags'][tag]}")
        print(f"     Raw record       : {result['raw']}")
        policy_notes = {
            "reject": "Strictest setting — mail failing DMARC alignment should be blocked outright.",
            "quarantine": "Moderate — mail failing alignment should be sent to spam/junk.",
            "none": "Monitoring only — failing mail is still delivered normally; this domain isn't enforcing anything yet.",
        }
        note = policy_notes.get(result["policy"])
        if note:
            print(f"\n  {note}")
    elif result["error"] is None:
        print("  ⚠️  No DMARC record published for this domain.")
        print("     Mail claiming to be from this domain has no DMARC-based protection against spoofing.")
    else:
        print(f"  ❓ Lookup inconclusive: {result['error']}")
        print("     (Try again, or check your network/DNS — this isn't a 'no record' result.)")
    print()


def cmd_history(args):
    rows = database.get_history(limit=args.limit)
    if not rows:
        print("No analyses recorded yet — run `phishguard analyze` or `phishguard batch` first.")
        return

    print(f"\n{'WHEN':<20} {'FILE':<28} {'SCORE':<6} {'VERDICT'}")
    print("-" * 90)
    for row in rows:
        when = row["analyzed_at"][:19].replace("T", " ")
        print(f"{when:<20} {(row['filename'] or '')[:27]:<28} {row['score']:<6} {row['verdict']}")
    print()


def cmd_stats(args):
    stats = database.get_stats()
    print("\n📊 PHISHGUARD — ALL-TIME STATS")
    print("-" * 40)
    print(f"  Total emails analyzed : {stats['total']}")
    print(f"  Average risk score    : {stats['avg_score']:.1f} / 100")
    print(f"  Highest score seen    : {stats['max_score']} / 100")
    print(f"  High-risk emails      : {stats['high_risk_count']}")
    print()


def main():
    p = argparse.ArgumentParser(prog="phishguard", description="Phishing email header analyzer")
    sub = p.add_subparsers(dest="command", required=True)

    p_analyze = sub.add_parser("analyze", help="Analyze a single .eml file")
    p_analyze.add_argument("file", help="Path to the .eml file")
    p_analyze.add_argument("--pdf", help="Also write a PDF report to this path")
    p_analyze.add_argument("--no-feed", action="store_true", help="Skip the live threat-feed check")
    p_analyze.add_argument("--no-dmarc", action="store_true", help="Skip the live DMARC DNS lookup")
    p_analyze.set_defaults(func=cmd_analyze)

    p_batch = sub.add_parser("batch", help="Analyze every .eml file in a folder")
    p_batch.add_argument("folder", help="Folder containing .eml files")
    p_batch.add_argument("--pdf", help="Also write a combined PDF report to this path")
    p_batch.add_argument("--no-feed", action="store_true", help="Skip the live threat-feed check")
    p_batch.add_argument("--no-dmarc", action="store_true", help="Skip the live DMARC DNS lookup")
    p_batch.set_defaults(func=cmd_batch)

    p_domain = sub.add_parser("check-domain", help="Check the DMARC record for any domain, standalone")
    p_domain.add_argument("domain", help="Domain to check, e.g. example.com")
    p_domain.add_argument("--timeout", type=float, default=5.0, help="DNS lookup timeout in seconds")
    p_domain.set_defaults(func=cmd_check_domain)

    p_history = sub.add_parser("history", help="Show past analyses recorded locally")
    p_history.add_argument("--limit", type=int, default=20)
    p_history.set_defaults(func=cmd_history)

    p_stats = sub.add_parser("stats", help="Show all-time aggregate stats")
    p_stats.set_defaults(func=cmd_stats)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
