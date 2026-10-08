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
    phishguard analyze suspicious.eml --feeds phishing-database   # use one feed only
    phishguard update-feeds                    # refresh the live threat feeds now
    phishguard build-snapshot --out feeds      # compact feed snapshot for the website
    phishguard history --limit 20
    phishguard stats
"""
import argparse
import glob
import os
import sys
from pathlib import Path

from . import database, dmarc, report, threat_feed
from .core import analyze_single


def _parse_feed_names(raw):
    if not raw:
        return None  # all feeds
    names = [n.strip() for n in raw.split(",") if n.strip()]
    unknown = [n for n in names if n not in threat_feed.FEED_SOURCES]
    if unknown:
        print(f"❌ Unknown feed(s): {', '.join(unknown)}. "
              f"Choose from: {', '.join(threat_feed.FEED_SOURCES)}", file=sys.stderr)
        sys.exit(2)
    return names


def _print_feed_status(statuses):
    notes = {
        "fresh": "downloaded just now",
        "cached": "up to date",
        "stale": "could not refresh — using an older cached copy",
        "offline": "unreachable and no cache — skipped",
    }
    for name, st in statuses.items():
        icon = "✅" if st["status"] in ("fresh", "cached") else "⚠️ "
        extra = f", {st['dropped']} shared-platform entries ignored" if st.get("dropped") else ""
        print(f"  {icon} {name}: {st['count']:,} entries ({notes[st['status']]}{extra})", file=sys.stderr)


def _get_feed(args):
    """Builds the live feed index, or returns None if feeds are disabled or all unreachable."""
    if args.no_feed:
        return None
    names = _parse_feed_names(args.feeds)
    print("🛰️  Threat feeds:", file=sys.stderr)
    index, statuses = threat_feed.build_index(names, force=args.refresh_feeds)
    _print_feed_status(statuses)
    if all(st["status"] == "offline" for st in statuses.values()):
        print("⚠️  No feed available — continuing without the live feed check.", file=sys.stderr)
        return None
    return index


def cmd_analyze(args):
    feed = _get_feed(args)
    result = analyze_single(args.file, feed=feed, check_dmarc=not args.no_dmarc)

    if result["error"]:
        print(f"❌ Error reading file: {result['error']}")
        sys.exit(1)

    report.print_report(
        result["headers"], result["ip_analysis"], result["keyword_findings"],
        result["score"], result["reasons"], result["verdict"],
        feed_matches=result["feed_matches"], feed_details=result["feed_match_details"],
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

    feed = _get_feed(args)
    print(f"🔍 Found {len(eml_files)} email(s) — analyzing...\n")

    all_results = []
    for file_path in eml_files:
        print("─" * 55)
        print(f"  Analyzing: {os.path.basename(file_path)}")
        print("─" * 55)

        result = analyze_single(file_path, feed=feed, check_dmarc=not args.no_dmarc)
        all_results.append(result)

        if result["error"]:
            print(f"  ❌ Error reading file: {result['error']}\n")
            continue

        report.print_report(
            result["headers"], result["ip_analysis"], result["keyword_findings"],
            result["score"], result["reasons"], result["verdict"],
            feed_matches=result["feed_matches"], feed_details=result["feed_match_details"],
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


def cmd_update_feeds(args):
    """Force-refresh the local copy of every (or the chosen) threat feed."""
    names = _parse_feed_names(args.feeds)
    print("🛰️  Refreshing threat feeds...")
    index, statuses = threat_feed.build_index(names, force=True)
    for name, st in statuses.items():
        print(f"  {name:18} {st['status']:8} {st['count']:>9,} entries   ({st['label']})")
        if st.get("dropped"):
            print(f"  {'':18} {'':8} {st['dropped']:>9,} shared-platform/hub entries ignored to avoid false positives")
    print(f"\nCached in {threat_feed.DEFAULT_CACHE_DIR}")
    if any(st["status"] in ("stale", "offline") for st in statuses.values()):
        sys.exit(1)


def cmd_build_snapshot(args):
    """Build the compact browser snapshot (used by the scheduled GitHub workflow)."""
    from . import snapshot
    names = _parse_feed_names(args.feeds) or snapshot.SNAPSHOT_DEFAULT_FEEDS
    try:
        meta = snapshot.build_snapshot(args.out, sources=names)
    except RuntimeError as e:
        print(f"❌ {e}", file=sys.stderr)
        sys.exit(1)
    size = (Path(args.out) / snapshot.BIN_NAME).stat().st_size
    print(f"✅ Snapshot written to {args.out}: {meta['entries']:,} fingerprints, {size/1e6:.1f} MB")


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
    elif result["error"] is None and result.get("domain_exists") is False:
        print("  ❓ This domain does not resolve in DNS (NXDOMAIN).")
        print("     Either it doesn't exist, or your network's DNS is blocking/hijacking lookups.")
    elif result["error"] is None and result.get("domain_exists") is True:
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
    p_analyze.add_argument("--feeds", help="Comma-separated feeds to use (default: all). "
                           f"Choices: {', '.join(threat_feed.FEED_SOURCES)}")
    p_analyze.add_argument("--refresh-feeds", action="store_true", help="Force a fresh download of the feeds")
    p_analyze.add_argument("--no-dmarc", action="store_true", help="Skip the live DMARC DNS lookup")
    p_analyze.set_defaults(func=cmd_analyze)

    p_batch = sub.add_parser("batch", help="Analyze every .eml file in a folder")
    p_batch.add_argument("folder", help="Folder containing .eml files")
    p_batch.add_argument("--pdf", help="Also write a combined PDF report to this path")
    p_batch.add_argument("--no-feed", action="store_true", help="Skip the live threat-feed check")
    p_batch.add_argument("--feeds", help="Comma-separated feeds to use (default: all). "
                           f"Choices: {', '.join(threat_feed.FEED_SOURCES)}")
    p_batch.add_argument("--refresh-feeds", action="store_true", help="Force a fresh download of the feeds")
    p_batch.add_argument("--no-dmarc", action="store_true", help="Skip the live DMARC DNS lookup")
    p_batch.set_defaults(func=cmd_batch)

    p_update = sub.add_parser("update-feeds", help="Download the latest copy of the live threat feeds")
    p_update.add_argument("--feeds", help="Comma-separated feeds to refresh (default: all)")
    p_update.set_defaults(func=cmd_update_feeds)

    p_snap = sub.add_parser("build-snapshot", help="Build the compact threat-feed snapshot used by the website")
    p_snap.add_argument("--out", default="feeds", help="Output folder (default: feeds)")
    p_snap.add_argument("--feeds", default=None, help="Comma-separated feeds (default: phishing-database)")
    p_snap.set_defaults(func=cmd_build_snapshot)

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
