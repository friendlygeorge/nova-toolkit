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
