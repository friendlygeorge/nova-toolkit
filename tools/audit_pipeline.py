#!/usr/bin/env python3
"""
Nova's Audit Pipeline — Reusable smart contract analysis tool.

Usage:
    # Analyze a local repo
    python3 audit_pipeline.py /path/to/contracts

    # Analyze a GitHub repo (clones first)
    python3 audit_pipeline.py https://github.com/user/repo

    # Analyze with custom solc version
    python3 audit_pipeline.py /path/to/contracts --solc 0.8.35

    # Filter by severity
    python3 audit_pipeline.py /path/to/contracts --min-severity medium

    # JSON output
    python3 audit_pipeline.py /path/to/contracts --json

    # Dry run (show what would be analyzed)
    python3 audit_pipeline.py /path/to/contracts --dry-run
"""

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Optional


# False positive patterns to filter
FALSE_POSITIVE_PATTERNS = [
    # Weak PRNG — often false positive for deterministic math (e.g., _rpow)
    r"weak-prng",
    # Incorrect equality — often intentional guards
    r"incorrect-equality",
    # Reentrancy with no ETH — usually safe for standard ERC-20
    r"reentrancy-no-eth",
    # Unused return — often intentional tuple destructuring
    r"unused-return",
    # Locked ether — often intentional
    r"locked-ether",
    # Delegatecall — often safe in proxy patterns
    r"delegatecall",
]

# Known safe patterns (for specific protocols)
SAFE_PATTERNS = {
    "makerdao": [
        r"incorrect-equality.*require\(now == rho\)",
        r"weak-prng.*_rpow",
        r"reentrancy.*nonReentrant",
    ],
    "openzeppelin": [
        r"reentrancy.*ReentrancyGuard",
    ],
}


class AuditPipeline:
    def __init__(self, target: str, solc_version: Optional[str] = None,
                 output_dir: Optional[str] = None, min_severity: str = "informational",
                 json_output: bool = False, dry_run: bool = False):
        self.target = target
        self.solc_version = solc_version
        self.output_dir = Path(output_dir or "/home/nova/output/audits")
        self.min_severity = min_severity
        self.json_output = json_output
        self.dry_run = dry_run
        self.findings = []
        self.stats = {
            "total": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "informational": 0,
            "false_positives": 0,
            "contracts_analyzed": 0,
            "lines_of_code": 0,
        }
        self.repo_name = self._extract_repo_name()

    def _extract_repo_name(self) -> str:
        """Extract repo name from URL or path."""
        if self.target.startswith("http"):
            # GitHub URL
            parts = self.target.rstrip("/").split("/")
            return parts[-1].replace(".git", "")
        else:
            return Path(self.target).name

    def _clone_repo(self, url: str) -> Path:
        """Clone a GitHub repo."""
        clone_dir = Path(tempfile.mkdtemp(prefix="audit_"))
        repo_dir = clone_dir / self.repo_name

        print(f"📦 Cloning {url}...")
        result = subprocess.run(
            ["git", "clone", "--depth", "1", url, str(repo_dir)],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode != 0:
            raise RuntimeError(f"Clone failed: {result.stderr}")

        print(f"✅ Cloned to {repo_dir}")
        return repo_dir

    def _find_sol_files(self, path: Path) -> list:
        """Find all .sol files in directory."""
        sol_files = []
        for sol in path.rglob("*.sol"):
            # Skip test files, node_modules, lib
            rel = str(sol.relative_to(path))
            if any(skip in rel for skip in ["test/", "tests/", "node_modules/", "lib/", ".git/"]):
                continue
            sol_files.append(sol)
        return sol_files

    def _detect_solc_version(self, sol_files: list) -> str:
        """Auto-detect solc version from pragma statements."""
        versions = set()
        for sol in sol_files[:20]:  # Sample first 20 files
            try:
                content = sol.read_text()[:2000]
                matches = re.findall(r"pragma solidity \^?([\d.]+)", content)
                for v in matches:
                    versions.add(v)
            except Exception:
                continue

        if not versions:
            return "0.8.35"  # Default

        # Pick highest version
        return sorted(versions)[-1]

    def _run_slither(self, target_path: Path) -> list:
        """Run Slither and parse output."""
        cmd = ["slither", str(target_path), "--json", "-"]
        if self.solc_version:
            cmd.extend(["--solc-solcs-select", self.solc_version])

        print(f"🔍 Running Slither...")
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=600
        )

        # Slither may exit with code 1 even with findings (not errors)
        if result.returncode > 1:
            print(f"⚠️  Slither exited with code {result.returncode}")
            print(f"   stderr: {result.stderr[:500]}")

        # Parse JSON output from stdout
        try:
            # Slither writes JSON to stdout when --json - is used
            output = result.stdout
            # Find the JSON object (skip any non-JSON lines)
            json_start = output.find("{")
            if json_start == -1:
                # Try stderr
                json_start = result.stderr.find("{")
                output = result.stderr

            if json_start >= 0:
                data = json.loads(output[json_start:])
                detectors = data.get("results", {}).get("detectors", [])
                self.stats["contracts_analyzed"] = len(
                    data.get("results", {}).get("contracts", [])
                )

                # Count lines of code
                for contract in data.get("results", {}).get("contracts", []):
                    for source in contract.get("sourcevinces", []):
                        self.stats["lines_of_code"] += source.get("length", 0)

                return detectors
        except json.JSONDecodeError as e:
            print(f"⚠️  Failed to parse Slither JSON: {e}")
            # Fall back to text parsing
            return self._parse_slither_text(result.stdout + result.stderr)

        return []

    def _parse_slither_text(self, text: str) -> list:
        """Parse Slither text output as fallback."""
        findings = []
        # Pattern: [Impact] [Confidence] finding_name: ... in ...
        pattern = r"\[(\w+)\]\s+\[(\w+)\]\s+(\w+:.*?)\n\s+(.*?)\n"
        for match in re.finditer(pattern, text):
            impact, confidence, name, location = match.groups()
            findings.append({
                "impact": impact.lower(),
                "confidence": confidence.lower(),
                "check": name.split(":")[0].strip(),
                "description": name,
                "additional": location,
            })
        return findings

    def _is_false_positive(self, finding: dict) -> bool:
        """Check if a finding is likely a false positive."""
        desc = finding.get("description", "").lower()
        check = finding.get("check", "").lower()
        combined = f"{desc} {check}"

        for pattern in FALSE_POSITIVE_PATTERNS:
            if re.search(pattern, combined, re.IGNORECASE):
                return True

        return False

    def _severity_order(self, severity: str) -> int:
        """Return numeric order for severity filtering."""
        order = {
            "critical": 0,
            "high": 1,
            "medium": 2,
            "low": 3,
            "informational": 4,
        }
        return order.get(severity.lower(), 5)

    def _filter_findings(self, detectors: list) -> list:
        """Filter and categorize findings."""
        filtered = []
        min_order = self._severity_order(self.min_severity)

        for det in detectors:
            # Normalize severity
            severity = det.get("impact", "informational").lower()
            if severity == "high":
                severity = "high"
            elif severity == "medium":
                severity = "medium"
            elif severity == "low":
                severity = "low"
            else:
                severity = "informational"

            # Check minimum severity
            if self._severity_order(severity) > min_order:
                continue

            # Check false positive
            is_fp = self._is_false_positive(det)
            if is_fp:
                self.stats["false_positives"] += 1
                det["_likely_false_positive"] = True
            else:
                det["_likely_false_positive"] = False

            det["_severity"] = severity
            filtered.append(det)

        return filtered

    def _generate_report(self) -> str:
        """Generate markdown report."""
        now = datetime.now().strftime("%Y-%m-%d %H:%M")
        lines = [
            f"# Audit Analysis Report — {self.repo_name}",
            f"*Generated: {now}*",
            "",
            "## Summary",
            "",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Target | `{self.target}` |",
            f"| Contracts Analyzed | {self.stats['contracts_analyzed']} |",
            f"| Lines of Code | {self.stats['lines_of_code']:,} |",
            f"| Total Findings | {self.stats['total']} |",
            f"| High | {self.stats['high']} |",
            f"| Medium | {self.stats['medium']} |",
            f"| Low | {self.stats['low']} |",
            f"| Informational | {self.stats['informational']} |",
            f"| Likely False Positives | {self.stats['false_positives']} |",
            "",
        ]

        # Non-false-positive findings by severity
        real_findings = [f for f in self.findings if not f.get("_likely_false_positive")]
        fp_findings = [f for f in self.findings if f.get("_likely_false_positive")]

        if real_findings:
            lines.append("## Findings (Excluding Likely False Positives)")
            lines.append("")

            for severity in ["high", "medium", "low", "informational"]:
                sev_findings = [f for f in real_findings if f.get("_severity") == severity]
                if sev_findings:
                    lines.append(f"### {severity.upper()} ({len(sev_findings)})")
                    lines.append("")
                    for i, f in enumerate(sev_findings, 1):
                        lines.append(f"**{i}. {f.get('check', 'Unknown')}**")
                        lines.append(f"- {f.get('description', 'No description')}")
                        if f.get("additional"):
                            lines.append(f"- Location: `{f.get('additional', '')[:200]}`")
                        lines.append("")

        if fp_findings:
            lines.append("## Likely False Positives (Filtered Out)")
            lines.append("")
            lines.append(f"*{len(fp_findings)} findings filtered as likely false positives.*")
            lines.append("")

            # Group by check type
            fp_types = {}
            for f in fp_findings:
                check = f.get("check", "Unknown")
                fp_types[check] = fp_types.get(check, 0) + 1

            for check, count in sorted(fp_types.items(), key=lambda x: -x[1]):
                lines.append(f"- **{check}**: {count}")

            lines.append("")

        # Recommendations
        lines.extend([
            "## Recommendations",
            "",
            "1. **Review high/medium findings manually** — automated analysis has false positives",
            "2. **Focus on cross-contract interactions** — most real bugs are in composability",
            "3. **Check economic logic** — parameter manipulation, oracle attacks, MEV vectors",
            "4. **Verify audit history** — find gaps in previous coverage",
            "5. **Write PoC exploits** — validate findings with concrete reproduction",
            "",
            "---",
            f"*Report generated by Nova's Audit Pipeline v1.0*",
        ])

        return "\n".join(lines)

    def run(self) -> dict:
        """Execute the audit pipeline."""
        print(f"🔬 Nova Audit Pipeline — Analyzing {self.repo_name}")
        print(f"   Target: {self.target}")
        print(f"   Min severity: {self.min_severity}")
        print()

        # Determine target path
        target_path = Path(self.target)
        if self.target.startswith("http"):
            if self.dry_run:
                print(f"📦 Would clone: {self.target}")
                return {"status": "dry_run", "target": self.target}
            target_path = self._clone_repo(self.target)

        if not target_path.exists():
            print(f"❌ Target not found: {target_path}")
            return {"status": "error", "message": "Target not found"}

        # Find sol files
        sol_files = self._find_sol_files(target_path)
        print(f"📄 Found {len(sol_files)} Solidity files")

        if not sol_files:
            print("❌ No Solidity files found")
            return {"status": "error", "message": "No Solidity files"}

        # Auto-detect solc if not specified
        if not self.solc_version:
            self.solc_version = self._detect_solc_version(sol_files)
            print(f"🔧 Detected solc version: {self.solc_version}")

        if self.dry_run:
            print(f"🔍 Would run Slither with solc {self.solc_version}")
            print(f"   Files: {[str(f.relative_to(target_path)) for f in sol_files[:10]]}")
            return {"status": "dry_run", "files": len(sol_files), "solc": self.solc_version}

        # Run Slither
        detectors = self._run_slither(target_path)
        print(f"📊 Slither found {len(detectors)} raw findings")

        # Filter and categorize
        self.findings = self._filter_findings(detectors)
        self.stats["total"] = len(self.findings)

        for f in self.findings:
            sev = f.get("_severity", "informational")
            self.stats[sev] = self.stats.get(sev, 0) + 1

        print(f"📊 After filtering: {self.stats['total']} findings")
        print(f"   High: {self.stats['high']} | Medium: {self.stats['medium']} | "
              f"Low: {self.stats['low']} | Info: {self.stats['informational']}")
        print(f"   Likely false positives: {self.stats['false_positives']}")

        # Generate report
        report = self._generate_report()

        # Save report
        self.output_dir.mkdir(parents=True, exist_ok=True)
        report_path = self.output_dir / f"{self.repo_name}-{datetime.now().strftime('%Y%m%d')}.md"
        report_path.write_text(report)
        print(f"\n📝 Report saved to {report_path}")

        # Save raw findings as JSON
        json_path = self.output_dir / f"{self.repo_name}-{datetime.now().strftime('%Y%m%d')}.json"
        json_path.write_text(json.dumps({
            "repo": self.repo_name,
            "target": self.target,
            "timestamp": datetime.now().isoformat(),
            "stats": self.stats,
            "findings": self.findings,
        }, indent=2, default=str))

        if self.json_output:
            print(json.dumps({
                "stats": self.stats,
                "report_path": str(report_path),
                "json_path": str(json_path),
            }, indent=2))
        else:
            print(f"\n✅ Audit complete!")
            print(f"   Report: {report_path}")
            print(f"   Data: {json_path}")

        return {
            "status": "success",
            "stats": self.stats,
            "report_path": str(report_path),
            "json_path": str(json_path),
        }


def main():
    parser = argparse.ArgumentParser(
        description="Nova's Audit Pipeline — Reusable smart contract analysis"
    )
    parser.add_argument("target", help="GitHub URL or local path to contracts")
    parser.add_argument("--solc", help="Solc version (auto-detected if not set)")
    parser.add_argument("--output", help="Output directory")
    parser.add_argument("--min-severity", default="informational",
                        choices=["critical", "high", "medium", "low", "informational"],
                        help="Minimum severity to include")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be analyzed")

    args = parser.parse_args()

    pipeline = AuditPipeline(
        target=args.target,
        solc_version=args.solc,
        output_dir=args.output,
        min_severity=args.min_severity,
        json_output=args.json,
        dry_run=args.dry_run,
    )

    result = pipeline.run()

    if result["status"] == "error":
        sys.exit(1)


if __name__ == "__main__":
    main()
