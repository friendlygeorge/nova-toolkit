#!/usr/bin/env python3
"""
Nova's Solidity Gas Optimization Analyzer

Identifies common gas waste patterns in Solidity contracts and suggests fixes.

Usage:
    # Analyze a single file
    python3 gas_optimizer.py /path/to/Contract.sol

    # Analyze a directory
    python3 gas_optimizer.py /path/to/contracts/

    # JSON output
    python3 gas_optimizer.py /path/to/Contract.sol --json

    # Filter by category
    python3 gas_optimizer.py /path/to/Contract.sol --category storage

    # Suggest only (no analysis)
    python3 gas_optimizer.py /path/to/Contract.sol --dry-run
"""

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import List, Optional, Dict, Tuple


class Severity(str, Enum):
    HIGH = "high"        # >1000 gas saved per occurrence
    MEDIUM = "medium"    # 200-1000 gas saved
    LOW = "low"          # <200 gas saved
    INFO = "info"        # Best practice, minimal gas impact


class Category(str, Enum):
    STORAGE = "storage"
    LOOP = "loop"
    ARITHMETIC = "arithmetic"
    STRUCT = "struct"
    FUNCTION = "function"
    DATA_LOCATION = "data_location"
    STRING = "string"
    MISCELLANEOUS = "miscellaneous"


@dataclass
class Finding:
    file: str
    line: int
    category: str
    severity: str
    title: str
    description: str
    gas_saved: str
    suggestion: str
    code_snippet: str = ""


@dataclass
class AnalysisReport:
    files_analyzed: int = 0
    total_lines: int = 0
    findings: List[Finding] = field(default_factory=list)
    summary: Dict = field(default_factory=dict)


# ─── Pattern Definitions ───────────────────────────────────────────────────

PATTERNS = [
    # ── Storage Patterns ──
    {
        "name": "storage_read_in_loop",
        "category": Category.LOOP,
        "severity": Severity.HIGH,
        "title": "Storage read inside loop",
        "description": "SLOAD costs 2100 gas (cold) or 100 gas (warm). "
                       "Reading storage inside a loop multiplies this cost. "
                       "Cache the value in a local variable before the loop.",
        "gas_saved": "~2000 gas per loop iteration",
        "pattern": re.compile(
            r'for\s*\([^)]*\)\s*\{[^}]*\b(\w+)\b\s*(?:[=><!+\-*/&|^%]|\b(?:is|in)\b)',
            re.MULTILINE | re.DOTALL
        ),
        "suggestion": "Cache storage variable in memory before the loop:\n"
                      "  uint cached = storageVar;\n"
                      "  for (uint i = 0; i < n; i++) { /* use cached */ }"
    },
    {
        "name": "storage_write_in_loop",
        "category": Category.LOOP,
        "severity": Severity.HIGH,
        "title": "Storage write inside loop",
        "description": "SSTORE costs 5000-20000 gas. Writing to storage in a loop "
                       "is extremely expensive. Consider using a local accumulator "
                       "and writing once after the loop.",
        "gas_saved": "~5000 gas per loop iteration",
        "pattern": re.compile(
            r'for\s*\([^)]*\)\s*\{[^}]*\b(\w+)\s*=\s*[^;]+;',
            re.MULTILINE | re.DOTALL
        ),
        "suggestion": "Use a memory accumulator:\n"
                      "  uint accumulator = 0;\n"
                      "  for (uint i = 0; i < n; i++) { accumulator += ...; }\n"
                      "  storageVar = accumulator;"
    },
    {
        "name": "mapping_read_in_loop",
        "category": Category.LOOP,
        "severity": Severity.HIGH,
        "title": "Mapping read inside loop",
        "description": "Mapping reads are SLOAD operations (2100 gas cold). "
                       "Reading the same mapping key repeatedly wastes gas.",
        "gas_saved": "~2000 gas per redundant read",
        "pattern": re.compile(
            r'for\s*\([^)]*\)\s*\{[^}]*\b\w+\[(\w+)\]',
            re.MULTILINE | re.DOTALL
        ),
        "suggestion": "Cache mapping values outside the loop or restructure the logic."
    },

    # ── Arithmetic Patterns ──
    {
        "name": "unchecked_safe_math",
        "category": Category.ARITHMETIC,
        "severity": Severity.MEDIUM,
        "title": "Safe arithmetic where overflow is impossible",
        "description": "Solidity 0.8+ has built-in overflow checks, but they cost gas. "
                       "If overflow is impossible (e.g., index incrementing), use "
                       "unchecked { } to save ~160 gas per operation.",
        "gas_saved": "~160 gas per operation",
        "pattern": re.compile(
            r'for\s*\([^)]*\)\s*\{[^}]*\b(\w+)\s*\+\+\s*;',
            re.MULTILINE | re.DOTALL
        ),
        "suggestion": "Use unchecked for safe increments:\n"
                      "  unchecked { i++; }"
    },
    {
        "name": "redundant_checked_division",
        "category": Category.ARITHMETIC,
        "severity": Severity.MEDIUM,
        "title": "Division with unnecessary overflow check",
        "description": "Division in Solidity 0.8+ reverts on zero divisor but "
                       "never overflows. The compiler still adds a check for "
                       "the dividend overflow which is unnecessary.",
        "gas_saved": "~20 gas per division",
        "pattern": re.compile(
            r'(?<!\bimport\s)(?<!\bfrom\s)\b(\w+)\s*/\s*(\w+)\s*[;=,)\]]',
            re.MULTILINE
        ),
        "suggestion": "This is compiler-level optimization; no code change needed. "
                      "Consider using Solidity >=0.8.10 for better optimizer output."
    },
    {
        "name": "exponentiation_with_literal",
        "category": Category.ARITHMETIC,
        "severity": Severity.LOW,
        "title": "Power of 2 computed via exponentiation",
        "description": "Using ** for powers of 2 is more expensive than bit shifting.",
        "gas_saved": "~20 gas",
        "pattern": re.compile(
            r'(\w+)\s*\*\*\s*(\d+)',
            re.MULTILINE
        ),
        "suggestion": "Replace x ** 2 with (x << 1), x ** 3 with (x << 2) + x, etc."
    },

    # ── Data Location Patterns ──
    {
        "name": "memory_to_calldata",
        "category": Category.DATA_LOCATION,
        "severity": Severity.MEDIUM,
        "title": "Function parameter uses 'memory' instead of 'calldata'",
        "description": "For external functions that only read array/struct/string "
                       "parameters, 'calldata' is cheaper than 'memory' because it "
                       "avoids copying the entire data to memory.",
        "gas_saved": "~200+ gas per calldata parameter",
        "pattern": re.compile(
            r'function\s+\w+\s*\([^)]*\b(\w+)\s+(?:string|bytes|uint\[\]|address\[\]|struct\s+\w+)\s+memory\b',
            re.MULTILINE
        ),
        "suggestion": "Change 'memory' to 'calldata' for external read-only parameters:\n"
                      "  function foo(string calldata data) external { ... }"
    },
    {
        "name": "struct_in_memory_readonly",
        "category": Category.DATA_LOCATION,
        "severity": Severity.MEDIUM,
        "title": "Struct parameter uses 'memory' when 'calldata' suffices",
        "description": "If a struct parameter is only read (not modified), using "
                       "'calldata' avoids the memory copy overhead.",
        "gas_saved": "~300+ gas per struct parameter",
        "pattern": re.compile(
            r'function\s+\w+\s*\([^)]*\b(\w+)\s+(\w+)\s+memory\b',
            re.MULTILINE
        ),
        "suggestion": "Use 'calldata' for external functions that don't modify the struct."
    },

    # ── Function Patterns ──
    {
        "name": "public_to_external",
        "category": Category.FUNCTION,
        "severity": Severity.MEDIUM,
        "title": "Public function could be external",
        "description": "Functions declared 'public' can be called both internally "
                       "and externally. If a function is never called internally, "
                       "declaring it 'external' saves gas by reading calldata directly.",
        "gas_saved": "~200+ gas per call",
        "pattern": re.compile(
            r'function\s+(\w+)\s*\([^)]*\)\s+public\b(?!\s+view\s*{)',
            re.MULTILINE
        ),
        "suggestion": "Change 'public' to 'external' if the function is never called internally."
    },
    {
        "name": "immutable_not_used",
        "category": Category.FUNCTION,
        "severity": Severity.MEDIUM,
        "title": "State variable could be 'immutable'",
        "description": "Variables set only in the constructor can be declared "
                       "'immutable', which embeds their value in bytecode instead "
                       "of reading from storage.",
        "gas_saved": "~2100 gas per read",
        "pattern": None,  # Requires multi-line analysis
        "suggestion": "Declare constructor-only variables as 'immutable':\n"
                      "  address public immutable owner;"
    },
    {
        "name": "constant_not_used",
        "category": Category.FUNCTION,
        "severity": Severity.LOW,
        "title": "State variable could be 'constant'",
        "description": "Variables that are never modified should be declared "
                       "'constant' to be inlined at compile time.",
        "gas_saved": "~100 gas per read (inlined)",
        "pattern": None,  # Requires multi-line analysis
        "suggestion": "Declare compile-time constant values:\n"
                      "  uint256 public constant MAX_SUPPLY = 10000;"
    },

    # ── String Patterns ──
    {
        "name": "string_concat_in_loop",
        "category": Category.STRING,
        "severity": Severity.HIGH,
        "title": "String concatenation inside loop",
        "description": "String concatenation with abi.encodePacked creates new "
                       "memory allocations. Doing this in a loop is very expensive.",
        "gas_saved": "Variable (depends on loop count)",
        "pattern": re.compile(
            r'for\s*\([^)]*\)\s*\{[^}]*abi\.encodePacked',
            re.MULTILINE | re.DOTALL
        ),
        "suggestion": "Build the string once after the loop, or use a different approach."
    },
    {
        "name": "error_string_gas",
        "category": Category.STRING,
        "severity": Severity.LOW,
        "title": "require() with error string",
        "description": "require() with a string message costs more gas than "
                       "require() without one. Consider using custom errors (Solidity 0.8.4+).",
        "gas_saved": "~100+ gas per require",
        "pattern": re.compile(
            r'require\s*\([^,]+,\s*"[^"]*"\s*\)',
            re.MULTILINE
        ),
        "suggestion": "Use custom errors for gas savings:\n"
                      "  error InsufficientBalance(uint256 available, uint256 required);\n"
                      "  if (bal < amount) revert InsufficientBalance(bal, amount);"
    },

    # ── Struct Patterns ──
    {
        "name": "struct_packing",
        "category": Category.STRUCT,
        "severity": Severity.MEDIUM,
        "title": "Struct fields may not be optimally packed",
        "description": "Solidity packs struct fields into 32-byte slots. Ordering "
                       "fields from smallest to largest can reduce storage slots.",
        "gas_saved": "~2100 gas per avoided slot",
        "pattern": None,  # Requires structural analysis
        "suggestion": "Reorder struct fields from smallest to largest type:\n"
                      "  struct User {\n"
                      "    uint8 status;    // 1 byte\n"
                      "    uint16 score;    // 2 bytes\n"
                      "    address addr;    // 20 bytes\n"
                      "    uint256 balance; // 32 bytes (new slot)\n"
                      "  }"
    },

    # ── Miscellaneous ──
    {
        "name": "redundant_state_variable_read",
        "category": Category.MISCELLANEOUS,
        "severity": Severity.LOW,
        "title": "Redundant state variable read",
        "description": "Reading a state variable multiple times in the same function "
                       "without writing in between wastes gas on repeated SLOADs.",
        "gas_saved": "~100-2100 gas per redundant read",
        "pattern": None,  # Requires flow analysis
        "suggestion": "Cache the state variable in a local variable."
    },
    {
        "name": "deprecated_transfer",
        "category": Category.MISCELLANEOUS,
        "severity": Severity.LOW,
        "title": "Use call() instead of transfer()",
        "description": "transfer() forwards only 2300 gas, which may not be enough "
                       "for contracts that need more gas in their receive() function.",
        "gas_saved": "N/A (reliability improvement)",
        "pattern": re.compile(
            r'\.transfer\s*\(',
            re.MULTILINE
        ),
        "suggestion": "Use call{value: amount}(\"\") instead of transfer(amount)."
    },
    {
        "name": "unchecked_block_number",
        "category": Category.MISCELLANEOUS,
        "severity": Severity.LOW,
        "title": "block.number used where block.timestamp would suffice",
        "description": "block.number is fine-grained but can be manipulated by miners. "
                       "For time-based logic, block.timestamp is preferred.",
        "gas_saved": "~3 gas (negligible, but best practice)",
        "pattern": re.compile(
            r'\bblock\.number\b',
            re.MULTILINE
        ),
        "suggestion": "Consider using block.timestamp for time-based logic."
    },
]


def analyze_file(filepath: str) -> Tuple[List[Finding], int]:
    """Analyze a single Solidity file for gas optimization patterns."""
    findings = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            lines = content.split('\n')
    except (IOError, UnicodeDecodeError) as e:
        return findings, 0

    total_lines = len(lines)

    for pattern_def in PATTERNS:
        if pattern_def["pattern"] is None:
            continue  # Skip patterns requiring multi-line analysis

        matches = pattern_def["pattern"].finditer(content)
        for match in matches:
            # Find line number
            line_num = content[:match.start()].count('\n') + 1
            if line_num > 0 and line_num <= len(lines):
                code_snippet = lines[line_num - 1].strip()
                if len(code_snippet) > 120:
                    code_snippet = code_snippet[:117] + "..."
            else:
                code_snippet = ""

            # Skip matches inside comments
            if code_snippet.startswith('//') or code_snippet.startswith('*'):
                continue

            finding = Finding(
                file=os.path.basename(filepath),
                line=line_num,
                category=pattern_def["category"].value,
                severity=pattern_def["severity"].value,
                title=pattern_def["title"],
                description=pattern_def["description"],
                gas_saved=pattern_def["gas_saved"],
                suggestion=pattern_def["suggestion"],
                code_snippet=code_snippet
            )
            findings.append(finding)

    # ─── Multi-line analysis (immutable/constant detection) ───
    # Detect state variables that are only set in constructor
    state_vars = {}
    constructor_vars = set()

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        # Skip comments
        if stripped.startswith('//') or stripped.startswith('*'):
            continue

        # Find state variable declarations (simplified)
        var_match = re.match(
            r'(?:address|uint\d*|bytes\d*|bool|string|mapping)\s+(?:public|private|internal)?\s*(\w+)',
            stripped
        )
        if var_match:
            var_name = var_match.group(1)
            state_vars[var_name] = i

    # Find constructor
    in_constructor = False
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if re.match(r'constructor\s*\(', stripped):
            in_constructor = True
            continue
        if in_constructor:
            if stripped == '}':
                in_constructor = False
                continue
            # Find assignments in constructor
            assign_match = re.search(r'(\w+)\s*=\s*', stripped)
            if assign_match:
                var_name = assign_match.group(1)
                if var_name in state_vars:
                    constructor_vars.add(var_name)

    # Check for immutable candidates
    for var_name, line_num in state_vars.items():
        if var_name in constructor_vars:
            # Check if already immutable
            if 'immutable' not in lines[line_num - 1]:
                finding = Finding(
                    file=os.path.basename(filepath),
                    line=line_num,
                    category=Category.FUNCTION.value,
                    severity=Severity.MEDIUM.value,
                    title="State variable could be 'immutable'",
                    description=f"Variable '{var_name}' appears to be set only in the constructor. "
                                 "Declaring it 'immutable' saves ~2100 gas per read by embedding "
                                 "the value in bytecode instead of storage.",
                    gas_saved="~2100 gas per read",
                    suggestion=f"Declare as immutable:\n  address public immutable {var_name};",
                    code_snippet=lines[line_num - 1].strip()[:120]
                )
                findings.append(finding)

    return findings, total_lines


def analyze_directory(dirpath: str, extensions: List[str] = None) -> AnalysisReport:
    """Analyze all Solidity files in a directory recursively."""
    if extensions is None:
        extensions = [".sol"]

    report = AnalysisReport()
    all_findings = []
    total_lines = 0
    files_analyzed = 0

    for root, dirs, files in os.walk(dirpath):
        # Skip common non-source directories
        dirs[:] = [d for d in dirs if d not in ['node_modules', '.git', 'lib', 'cache', 'out', 'build']]

        for filename in sorted(files):
            if any(filename.endswith(ext) for ext in extensions):
                filepath = os.path.join(root, filename)
                findings, lines = analyze_file(filepath)
                all_findings.extend(findings)
                total_lines += lines
                files_analyzed += 1

    report.files_analyzed = files_analyzed
    report.total_lines = total_lines
    report.findings = all_findings

    # Generate summary
    severity_counts = {}
    category_counts = {}
    for f in all_findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
        category_counts[f.category] = category_counts.get(f.category, 0) + 1

    report.summary = {
        "total_findings": len(all_findings),
        "by_severity": severity_counts,
        "by_category": category_counts,
    }

    return report


def format_markdown(report: AnalysisReport) -> str:
    """Format analysis report as markdown."""
    lines = []
    lines.append("# 🔍 Gas Optimization Report\n")

    # Summary
    lines.append("## Summary\n")
    lines.append(f"- **Files analyzed:** {report.files_analyzed}")
    lines.append(f"- **Total lines:** {report.total_lines:,}")
    lines.append(f"- **Total findings:** {report.summary.get('total_findings', 0)}")

    if report.summary.get('by_severity'):
        lines.append("\n### By Severity\n")
        for sev, count in sorted(report.summary['by_severity'].items()):
            emoji = {"high": "🔴", "medium": "🟡", "low": "🟢", "info": "ℹ️"}.get(sev, "⚪")
            lines.append(f"- {emoji} **{sev.upper()}:** {count}")

    if report.summary.get('by_category'):
        lines.append("\n### By Category\n")
        for cat, count in sorted(report.summary['by_category'].items(), key=lambda x: -x[1]):
            lines.append(f"- **{cat.title()}:** {count}")

    lines.append("")

    # Findings by severity
    for severity in ["high", "medium", "low", "info"]:
        sev_findings = [f for f in report.findings if f.severity == severity]
        if not sev_findings:
            continue

        emoji = {"high": "🔴", "medium": "🟡", "low": "🟢", "info": "ℹ️"}.get(severity, "⚪")
        lines.append(f"## {emoji} {severity.upper()} Severity ({len(sev_findings)} findings)\n")

        for i, finding in enumerate(sev_findings, 1):
            lines.append(f"### {i}. {finding.title}")
            lines.append(f"- **File:** `{finding.file}` (line {finding.line})")
            lines.append(f"- **Category:** {finding.category}")
            lines.append(f"- **Gas saved:** {finding.gas_saved}")
            lines.append(f"- **Description:** {finding.description}")
            if finding.code_snippet:
                lines.append(f"- **Code:** `{finding.code_snippet}`")
            lines.append(f"- **Suggestion:**")
            for sline in finding.suggestion.split('\n'):
                lines.append(f"  {sline}")
            lines.append("")

    if not report.findings:
        lines.append("## ✅ No gas optimization issues found!\n")
        lines.append("The analyzed contracts appear to follow gas-efficient patterns.")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Nova's Solidity Gas Optimization Analyzer"
    )
    parser.add_argument(
        "path",
        help="Path to Solidity file or directory"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output as JSON"
    )
    parser.add_argument(
        "--category",
        choices=[c.value for c in Category],
        help="Filter findings by category"
    )
    parser.add_argument(
        "--severity",
        choices=[s.value for s in Severity],
        help="Filter findings by minimum severity"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show analysis plan without executing"
    )
    parser.add_argument(
        "--min-severity",
        choices=[s.value for s in Severity],
        default="info",
        help="Minimum severity to report (default: info)"
    )

    args = parser.parse_args()

    if args.dry_run:
        print("🔍 Gas Optimization Analysis Plan")
        print(f"   Target: {args.path}")
        print(f"   Patterns: {len(PATTERNS)} rules")
        print(f"   Categories: {', '.join(c.value for c in Category)}")
        print(f"   Min severity: {args.min_severity}")
        return

    # Check path exists
    if not os.path.exists(args.path):
        print(f"Error: Path not found: {args.path}", file=sys.stderr)
        sys.exit(1)

    # Analyze
    if os.path.isfile(args.path):
        findings, lines = analyze_file(args.path)
        report = AnalysisReport(
            files_analyzed=1,
            total_lines=lines,
            findings=findings,
            summary={
                "total_findings": len(findings),
                "by_severity": {},
                "by_category": {},
            }
        )
        for f in findings:
            report.summary["by_severity"][f.severity] = report.summary["by_severity"].get(f.severity, 0) + 1
            report.summary["by_category"][f.category] = report.summary["by_category"].get(f.category, 0) + 1
    else:
        report = analyze_directory(args.path)

    # Filter by severity
    severity_order = ["info", "low", "medium", "high"]
    min_idx = severity_order.index(args.min_severity) if args.min_severity in severity_order else 0
    report.findings = [
        f for f in report.findings
        if severity_order.index(f.severity) >= min_idx
    ]

    # Filter by category
    if args.category:
        report.findings = [f for f in report.findings if f.category == args.category]

    # Sort by severity (high first) then by line number
    severity_order_map = {"high": 0, "medium": 1, "low": 2, "info": 3}
    report.findings.sort(key=lambda f: (severity_order_map.get(f.severity, 4), f.line))

    # Output
    if args.json:
        output = {
            "files_analyzed": report.files_analyzed,
            "total_lines": report.total_lines,
            "summary": report.summary,
            "findings": [asdict(f) for f in report.findings],
        }
        print(json.dumps(output, indent=2))
    else:
        print(format_markdown(report))


if __name__ == "__main__":
    main()
