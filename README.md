# Nova Toolkit

Nova's smart contract security toolkit — audit tools, bounty scripts, and analysis utilities for Solidity and EVM-based protocols.

> Built and maintained by Nova ([@friendlygeorge](https://github.com/friendlygeorge)).

## Overview

`nova-toolkit` is a curated collection of resources Nova uses to:

- **Audit** smart contracts (static analysis helpers, checklists, report templates)
- **Hunt bounties** on DeFi / NFT / bridge protocols (recon scripts, PoC scaffolds)
- **Analyze** on-chain activity (forks, heuristics, gas/storage pattern utilities)

The goal is fast, repeatable workflows — small, composable tools that can be mixed and matched per engagement.

## Repository Layout

```
nova-toolkit/
├── audits/        # Audit report templates, finding catalogs, checklists
├── bounties/      # Bug bounty recon and PoC scripts
├── tools/         # Standalone analysis utilities (CLI tools, helpers)
├── contracts/     # Sample / vulnerable contracts used for testing
├── scripts/       # One-off automation and glue scripts
└── docs/          # Methodology notes, references, write-ups
```

## Quick Start

```bash
git clone https://github.com/friendlygeorge/nova-toolkit.git
cd nova-toolkit

# Most tools are Node.js based
node --version   # >= 18
npm --version

# Optional: install common deps (Slither, Foundry, etc.) — see docs/setup.md
```

## Tooling Stack

- **Languages:** Solidity, TypeScript / JavaScript, Python
- **Static analysis:** Slither, Mythril, Aderyn
- **Fuzzing / testing:** Foundry (`forge`), Echidna
- **On-chain:** Ethers.js, Viem, Cast
- **Reporting:** Markdown templates, custom scripts

## Conventions

- Every tool lives in its own folder with a `README.md` and (where applicable) a `package.json` or `foundry.toml`.
- Findings follow the standard severity model: `Critical` / `High` / `Medium` / `Low` / `Informational`.
- Public bounty PoCs target **mainnet** only after a responsible-disclosure process — see `docs/disclosure.md`.
- No private keys, RPC endpoints with secrets, or unreported vulnerabilities are ever committed.

## Responsible Use

This toolkit is for **defensive security and authorized auditing** only. Always:

1. Get explicit scope and authorization before testing.
2. Respect bug bounty program rules (Immunefi, Code4rena, Sherlock, etc.).
3. Disclose findings privately and give teams a reasonable remediation window.

## Contributing

This is Nova's personal working repo — contributions are not currently accepted. Issues / suggestions can be opened for personal tracking.

## License

MIT — see [`LICENSE`](./LICENSE).

## Available Tools

| Tool | Description | Status |
|------|-------------|--------|
| `tools/audit_pipeline.py` | Smart contract static analysis with Slither | ✅ Production |
| `tools/sentinel.py` | Wallet balance monitoring and alerting | ✅ Production |
| `tools/bounty_scanner.py` | Immunefi bounty program scanner | ✅ Production |
| `tools/gas_optimizer.py` | Solidity gas optimization analysis | ✅ Production |
| `tools/security_scanner.py` | On-chain security scanner for Base | ✅ Production |

### audit_pipeline.py

Reusable smart contract analysis tool. Run Slither on any Solidity codebase with automatic false-positive filtering and report generation.

```bash
python3 tools/audit_pipeline.py https://github.com/user/repo --min-severity medium
python3 tools/audit_pipeline.py /path/to/contract.sol
```

### bounty_scanner.py

Scans Immunefi's bug bounty programs via their unofficial GitHub API. Filters by chain, KYC status, and bounty size.

```bash
python3 tools/bounty_scanner.py --chain base --no-kyc --min-bounty 10000
```

### gas_optimizer.py

Analyzes Solidity contracts for gas optimization opportunities. Identifies storage packing, loop inefficiencies, and redundant operations.

```bash
python3 tools/gas_optimizer.py /path/to/contract.sol
```

### sentinel.py

Wallet balance monitoring with anomaly detection. Tracks ETH and ERC-20 balances, compares to last known state, and generates alerts for unexpected changes.

```bash
python3 tools/sentinel.py
```

See [tools/README.md](tools/README.md) for full documentation.
