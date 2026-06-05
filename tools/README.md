# Tools

## audit_pipeline.py

Reusable smart contract analysis tool powered by Slither. Analyzes Solidity codebases for security vulnerabilities with automatic false-positive filtering.

### Features
- **Auto-detects solc version** from pragma statements
- **Filters likely false positives** (weak-prng, incorrect-equality, reentrancy-no-eth, etc.)
- **Generates markdown + JSON reports** with severity breakdown
- **GitHub URL support** — clones repos automatically
- **Severity filtering** — focus on medium+ findings
- **Dry run mode** — preview before committing

### Usage

```bash
# Analyze a local repo
python3 audit_pipeline.py /path/to/contracts

# Analyze a GitHub repo (clones first)
python3 audit_pipeline.py https://github.com/user/repo

# Filter by severity
python3 audit_pipeline.py /path/to/contracts --min-severity medium

# JSON output for automation
python3 audit_pipeline.py /path/to/contracts --json
```

### Requirements
- Python 3.8+
- Slither (`pip install slither-analyzer`)
- solc (auto-detected or specify with `--solc`)

### Example Output

```
=== Audit Report: AlchemistV3 ===
Analyzed: 89 files
Findings: 128 total
  High: 1 (false positive — Solady modular inverse pattern)
  Medium: 50 (28 incorrect-equality, 9 divide-before-multiply)
  Low: 45
  Informational: 32
```

## sentinel.py

Wallet monitoring script that checks token balances and alerts on anomalies.

### Features
- Checks USDC (raw + Aave receipt tokens) and ETH balances
- Detects >5% USDC or >10% ETH changes
- Writes alerts to a file for cron job processing
- Maintains persistent state across runs

### Usage

```bash
# Run once
python3 sentinel.py

# Output: JSON with balances and any alerts generated
```

### Setup
1. Set `NOVA_WALLET_PRIVATE_KEY` env var
2. Set `ALCHEMY_API_KEY` env var
3. Run via cron every 30 minutes

## security_scanner.py

On-chain security scanner for Base contracts. Fetches verified source code from Sourcify (free, no API key), runs 14 pattern-based security checks, and generates findings with severity ratings.

### Features
- **Source code retrieval via Sourcify** — free, no API key, covers Base chain
- **14 security checks**: reentrancy, access control, unchecked calls, tx.origin, selfdestruct, delegatecall, timestamp dependence, integer overflow, flash loan exposure, oracle manipulation, upgradeability, centralization, missing events, gas griefing, first deposit attack
- **Severity ratings** — High/Medium/Low/Info for each finding
- **Markdown + JSON output** — human-readable and machine-parseable
- **Bytecode verification** — confirms contract is actually deployed before scanning

### Usage
```bash
# Scan a contract on Base
python3 security_scanner.py 0xA238Dd80C259a72e81d7e4664a9801593F98d1c5

# JSON output
python3 security_scanner.py 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913 --json

# Save report to file
python3 security_scanner.py <address> --output report.md
```

### Requirements
- Python 3.8+
- requests
- web3 (for checksum addresses)

### Example Output
```
[*] Scanning 0xA238Dd80C259a72e81d7e4664a9801593F98d1c5...
[*] Contract found (1933 bytes)
[*] Source code fetched from Sourcify (1 file, 4892 chars)
[*] Running 14 security checks...

=== Security Report: Aave V3 Pool ===
Address: 0xA238Dd80C259a72e81d7e4664a9801593F98d1c5
Compiler: v0.8.19+commit.7dd6d404

Findings: 3 total
  High: 0
  Medium: 1 (upgradeability — proxy pattern detected)
  Low: 1 (centralization — owner has admin role)
  Info: 1 (missing events on state change)
```
