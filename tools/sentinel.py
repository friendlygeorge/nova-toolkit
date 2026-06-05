#!/usr/bin/env python3
"""
Nova's Sentinel — Wallet balance monitor and alert writer.
Run periodically to detect anomalies and write alerts.
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# Paths
STATE_FILE = Path("/home/nova/output/logs/wallet-state.json")
ALERTS_FILE = Path("/home/nova/output/logs/alerts.md")
WALLET = "0x46bc982375eB3d8bf5F29E63d95FA156F8868b9D"

# Thresholds
BALANCE_CHANGE_PCT = 5  # Alert if balance changes by >5%
ETH_CHANGE_PCT = 10     # Alert if ETH changes by >10%

def get_balances():
    """Get current wallet balances via Base RPC."""
    try:
        from web3 import Web3
        
        rpc_url = os.environ.get("BASE_RPC_URL", "https://mainnet.base.org")
        w3 = Web3(Web3.HTTPProvider(rpc_url))
        
        if not w3.is_connected():
            return None, "RPC connection failed"
        
        wallet = w3.to_checksum_address(WALLET)
        
        # ETH balance
        eth_balance = w3.eth.get_balance(wallet)
        eth = float(w3.from_wei(eth_balance, 'ether'))
        
        # USDC balance (Base USDC: 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913)
        ERC20_ABI = json.loads('[{"constant":true,"inputs":[{"name":"_owner","type":"address"}],"name":"balanceOf","outputs":[{"name":"balance","type":"uint256"}],"type":"function"}]')
        
        # Raw USDC
        usdc_contract = w3.eth.contract(
            address=w3.to_checksum_address("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"),
            abi=ERC20_ABI
        )
        usdc_raw = usdc_contract.functions.balanceOf(wallet).call()
        usdc = usdc_raw / 1e6
        
        # aBasUSDC (Aave interest-bearing USDC: 0x4e65fE4DbA92790696d040ac24Aa414708F5c0AB)
        abas_contract = w3.eth.contract(
            address=w3.to_checksum_address("0x4e65fE4DbA92790696d040ac24Aa414708F5c0AB"),
            abi=ERC20_ABI
        )
        abas_raw = abas_contract.functions.balanceOf(wallet).call()
        abas_usdc = abas_raw / 1e6
        
        # Total USDC value (raw + Aave)
        total_usdc = usdc + abas_usdc
        
        return {"eth": eth, "usdc": usdc, "abas_usdc": abas_usdc, "total_usdc": total_usdc, "timestamp": datetime.now(timezone.utc).isoformat()}, None
        
    except Exception as e:
        return None, str(e)

def load_state():
    """Load last known state."""
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except:
            return None
    return None

def save_state(state):
    """Save current state."""
    STATE_FILE.write_text(json.dumps(state, indent=2))

def check_alerts_exist():
    """Check if there are unhandled alerts."""
    if not ALERTS_FILE.exists():
        return False
    content = ALERTS_FILE.read_text()
    return "- [ ] " in content  # Unhandled alerts start with "- [ ] "

def write_alert(severity, message):
    """Append an alert to alerts.md."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    
    if not ALERTS_FILE.exists():
        ALERTS_FILE.write_text("# Nova Alerts\n\nUnhandled alerts require action.\nHandled alerts are marked [x].\n\n---\n\n")
    
    with open(ALERTS_FILE, "a") as f:
        f.write(f"- [ ] **[{severity}]** {timestamp} — {message}\n")
    
    print(f"ALERT: [{severity}] {message}")

def main():
    # Get current balances
    current, error = get_balances()
    
    if error:
        write_alert("HIGH", f"Balance check failed: {error}")
        print(json.dumps({"status": "error", "error": error}))
        return
    
    # Load previous state
    previous = load_state()
    
    # Save current state
    save_state(current)
    
    # First run — just save state, no comparison
    if previous is None:
        print(json.dumps({"status": "initialized", "current": current}))
        return
    
    # Compare balances
    alerts = []
    
    # USDC change (total including Aave)
    if previous["total_usdc"] > 0:
        usdc_change_pct = ((current["total_usdc"] - previous["total_usdc"]) / previous["total_usdc"]) * 100
        if abs(usdc_change_pct) > BALANCE_CHANGE_PCT:
            direction = "increased" if usdc_change_pct > 0 else "decreased"
            severity = "HIGH" if usdc_change_pct < -BALANCE_CHANGE_PCT else "MEDIUM"
            write_alert(severity, f"USDC {direction} by {abs(usdc_change_pct):.1f}% (${previous['total_usdc']:.2f} → ${current['total_usdc']:.2f})")
            alerts.append(f"USDC {direction}")
    
    # ETH change
    if previous["eth"] > 0:
        eth_change_pct = ((current["eth"] - previous["eth"]) / previous["eth"]) * 100
        if abs(eth_change_pct) > ETH_CHANGE_PCT:
            direction = "increased" if eth_change_pct > 0 else "decreased"
            write_alert("MEDIUM", f"ETH {direction} by {abs(eth_change_pct):.1f}% ({previous['eth']:.6f} → {current['eth']:.6f})")
            alerts.append(f"ETH {direction}")
    
    # Output result
    result = {
        "status": "ok",
        "current": current,
        "previous": previous,
        "alerts": alerts,
        "alerts_exist": check_alerts_exist()
    }
    print(json.dumps(result))

if __name__ == "__main__":
    main()
