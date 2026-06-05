#!/usr/bin/env python3
"""
Bounty Scanner — Monitor multiple bounty platforms and surface opportunities.

Sources: GitHub Issues, Immunefi Programs, Code4rena, Sherlock
Filters: Blacklist, quality (GSSoC, low-value, stale)
Ranking: Expected value = (payout × confidence) / effort

Usage:
    python3 scanner.py                    # Full scan
    python3 scanner.py --source github    # GitHub only
    python3 scanner.py --min-payout 100   # Filter low-value
    python3 scanner.py --json             # JSON output
"""

import argparse
import json
import sys
import os
from datetime import datetime, timedelta, timezone

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sources.github import scan_github
from sources.immunefi import scan_immunefi
from sources.c4 import scan_c4
from filters.blacklist import load_blacklist, filter_blacklisted
from filters.quality import filter_quality
from ranker import rank_opportunities


def parse_args():
    parser = argparse.ArgumentParser(description="Bounty Scanner — Find bounty opportunities across platforms")
    parser.add_argument("--source", choices=["github", "immunefi", "c4", "all"], default="all",
                        help="Source to scan (default: all)")
    parser.add_argument("--min-payout", type=float, default=0,
                        help="Minimum payout filter (default: 0)")
    parser.add_argument("--blacklist", default="/home/nova/blacklist.md",
                        help="Blacklist file path")
    parser.add_argument("--output", default="/home/nova/output/research/bounty-opportunities.md",
                        help="Output file path")
    parser.add_argument("--json", action="store_true",
                        help="Output as JSON instead of markdown")
    parser.add_argument("--no-filter", action="store_true",
                        help="Skip quality filters")
    return parser.parse_args()


def main():
    args = parse_args()
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    
    # Load blacklist
    blacklist = load_blacklist(args.blacklist)
    
    # Scan sources
    opportunities = []
    
    if args.source in ("github", "all"):
        print("Scanning GitHub bounties...", file=sys.stderr)
        github_opps = scan_github()
        opportunities.extend(github_opps)
        print(f"  Found {len(github_opps)} GitHub bounties", file=sys.stderr)
    
    if args.source in ("immunefi", "all"):
        print("Scanning Immunefi programs...", file=sys.stderr)
        immunefi_opps = scan_immunefi()
        opportunities.extend(immunefi_opps)
        print(f"  Found {len(immunefi_opps)} Immunefi programs", file=sys.stderr)
    
    if args.source in ("c4", "all"):
        print("Scanning Code4rena contests...", file=sys.stderr)
        c4_opps = scan_c4()
        opportunities.extend(c4_opps)
        print(f"  Found {len(c4_opps)} C4 contests", file=sys.stderr)
    
    # Filter
    if not args.no_filter:
        opportunities = filter_blacklisted(opportunities, blacklist)
        opportunities = filter_quality(opportunities)
    
    if args.min_payout > 0:
        opportunities = [o for o in opportunities if o.get("payout", 0) >= args.min_payout]
    
    # Rank
    opportunities = rank_opportunities(opportunities, now)
    
    # Output
    if args.json:
        print(json.dumps(opportunities, indent=2, default=str))
    else:
        generate_markdown(opportunities, args.output, now)
        print(f"\nReport written to {args.output}", file=sys.stderr)
        print(f"Total opportunities: {len(opportunities)}", file=sys.stderr)


def generate_markdown(opportunities, output_path, now):
    """Generate a markdown report of opportunities."""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    lines = [
        f"# Bounty Opportunities — {now.strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        f"**Total opportunities:** {len(opportunities)}",
        "",
    ]
    
    # Group by source
    by_source = {}
    for opp in opportunities:
        source = opp.get("source", "unknown")
        by_source.setdefault(source, []).append(opp)
    
    source_icons = {
        "github": "🐙",
        "immunefi": "🛡️",
        "c4": "🏆",
        "sherlock": "🔍",
    }
    
    for source, opps in sorted(by_source.items()):
        icon = source_icons.get(source, "📌")
        lines.append(f"## {icon} {source.title()} ({len(opps)} opportunities)")
        lines.append("")
        
        for opp in opps[:20]:  # Top 20 per source
            payout = opp.get("payout", 0)
            payout_str = f"${payout:,.0f}" if payout else "Unknown"
            effort = opp.get("effort_hours", "?")
            ev = opp.get("ev_score", 0)
            title = opp.get("title", "Unknown")[:70]
            url = opp.get("url", "")
            repo = opp.get("repo", "")
            labels = ", ".join(opp.get("labels", [])[:3])
            created = opp.get("created", "")
            
            lines.append(f"### {title}")
            lines.append(f"- **Payout:** {payout_str} | **Effort:** {effort}h | **EV Score:** {ev:.1f}")
            if repo:
                lines.append(f"- **Repo:** {repo}")
            if labels:
                lines.append(f"- **Labels:** {labels}")
            if created:
                lines.append(f"- **Created:** {created}")
            if url:
                lines.append(f"- **Link:** {url}")
            lines.append("")
    
    # Summary
    lines.append("---")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    
    total_payout = sum(o.get("payout", 0) for o in opportunities if o.get("payout"))
    avg_ev = sum(o.get("ev_score", 0) for o in opportunities) / len(opportunities) if opportunities else 0
    
    lines.append(f"- **Total estimated payout:** ${total_payout:,.0f}")
    lines.append(f"- **Average EV score:** {avg_ev:.1f}")
    lines.append(f"- **Sources scanned:** {', '.join(by_source.keys())}")
    lines.append(f"- **Generated:** {now.strftime('%Y-%m-%d %H:%M UTC')}")
    lines.append("")
    
    with open(output_path, "w") as f:
        f.write("\n".join(lines))


if __name__ == "__main__":
    main()
