#!/usr/bin/env python3
"""Swap tokens on Base through Uniswap V3 SwapRouter02.

Usage:
    python3 swap.py <from_symbol> <to_symbol> <amount> [--slippage BPS] [--dry-run]

Examples:
    python3 swap.py ETH USDC 0.01
    python3 swap.py USDC ETH 10 --slippage 50
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from decimal import Decimal, InvalidOperation, ROUND_DOWN, getcontext
from typing import Any

from web3 import Web3

from web3_core import (
    BASE_CHAIN_ID,
    TOKENS,
    UNISWAP_SWAP_ROUTER_02,
    eip1559_fees,
    get_address,
    get_nonce,
    get_router_contract,
    get_token_contract,
    get_w3,
    sign_and_send,
)

getcontext().prec = 80

DEFAULT_FEE_TIER = 500  # 0.05%; default for WETH/USDC on Base.
MAX_UINT256 = 2**256 - 1


def fmt(value: Decimal, places: int = 8) -> str:
    quant = Decimal(1).scaleb(-places)
    text = format(value.quantize(quant), "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return text or "0"


def token_lookup(symbol: str) -> dict[str, Any]:
    upper = symbol.upper()
    if upper == "ETH":
        weth = TOKENS.get("WETH")
        if not weth:
            raise ValueError("WETH is not configured in web3_core.TOKENS")
        return {
            "input_symbol": "ETH",
            "symbol": "ETH",
            "router_symbol": "WETH",
            "address": weth["address"],
            "decimals": 18,
            "native": True,
            "name": "Ether",
        }
    for key, token in TOKENS.items():
        token_symbol = str(token.get("symbol", key))
        if key.upper() == upper or token_symbol.upper() == upper:
            return {
                "input_symbol": symbol,
                "symbol": token_symbol,
                "router_symbol": token_symbol,
                "address": token["address"],
                "decimals": int(token.get("decimals", 18)),
                "native": False,
                "name": token.get("name", token_symbol),
            }
    available = ", ".join(["ETH", *[str(v.get("symbol", k)) for k, v in TOKENS.items()]])
    raise ValueError(f"Unknown token symbol '{symbol}'. Available: {available}")


def parse_amount(amount: str, decimals: int) -> int:
    try:
        dec = Decimal(amount)
    except InvalidOperation:
        raise ValueError(f"Invalid amount: {amount}") from None
    if dec <= 0:
        raise ValueError("Amount must be greater than zero")
    raw_decimal = (dec * (Decimal(10) ** decimals)).quantize(Decimal("1"), rounding=ROUND_DOWN)
    if raw_decimal != dec * (Decimal(10) ** decimals):
        raise ValueError(f"Amount has more precision than token supports ({decimals} decimals)")
    raw = int(raw_decimal)
    if raw <= 0:
        raise ValueError("Amount is too small for token decimals")
    return raw


def from_units(raw: int, decimals: int) -> Decimal:
    return Decimal(raw) / (Decimal(10) ** decimals)


def tx_hash_hex(value: Any) -> str:
    text = value.hex() if hasattr(value, "hex") else str(value)
    return text if text.startswith("0x") else f"0x{text}"


def normalize_fees() -> dict[str, int]:
    fees = eip1559_fees()
    return {"maxFeePerGas": int(fees["maxFeePerGas"]), "maxPriorityFeePerGas": int(fees["maxPriorityFeePerGas"]), "type": 2}


def build_base_tx(from_address: str, nonce: int, value: int = 0) -> dict[str, Any]:
    tx = {
        "from": from_address,
        "chainId": BASE_CHAIN_ID,
        "nonce": nonce,
        "value": value,
    }
    tx.update(normalize_fees())
    return tx


def get_eth_price_usd() -> Decimal:
    """Fetch ETH/USD price from CoinGecko (free, no API key)."""
    url = "https://api.coingecko.com/api/v3/simple/price?ids=ethereum&vs_currencies=usd"
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            data = json.loads(resp.read())
            return Decimal(str(data["ethereum"]["usd"]))
    except Exception as exc:
        raise RuntimeError(f"Failed to fetch ETH price from CoinGecko: {exc}") from exc


def estimate_output(
    from_token: dict[str, Any],
    to_token: dict[str, Any],
    amount_in: int,
    eth_price: Decimal,
) -> int:
    """Estimate swap output using CoinGecko prices (rough estimate, slippage buffer handles accuracy)."""
    in_decimals = int(from_token["decimals"])
    out_decimals = int(to_token["decimals"])
    in_amount = Decimal(amount_in) / (Decimal(10) ** in_decimals)

    from_sym = from_token["symbol"].upper()
    to_sym = to_token["symbol"].upper()

    # Map known stablecoins to $1
    stablecoins = {"USDC", "USDT", "DAI", "USDBC", "PYUSD"}

    if from_sym in stablecoins and to_sym == "ETH":
        out_amount = in_amount / eth_price
    elif from_sym in stablecoins and to_sym == "WETH":
        out_amount = in_amount / eth_price
    elif from_sym == "ETH" and to_sym in stablecoins:
        out_amount = in_amount * eth_price
    elif from_sym == "WETH" and to_sym in stablecoins:
        out_amount = in_amount * eth_price
    elif from_sym in stablecoins and to_sym in stablecoins:
        # Stablecoin to stablecoin, assume 1:1
        out_amount = in_amount
    elif from_sym == "ETH" and to_sym == "WETH":
        out_amount = in_amount
    elif from_sym == "WETH" and to_sym == "ETH":
        out_amount = in_amount
    elif from_sym in stablecoins:
        # Unknown token - use ETH price as rough proxy
        out_amount = in_amount / eth_price  # Very rough
    elif to_sym in stablecoins:
        # Unknown token - use ETH price as rough proxy
        out_amount = in_amount * eth_price
    else:
        # Both unknown - can't estimate, use 1:1 as fallback
        out_amount = in_amount

    return int(out_amount * (Decimal(10) ** out_decimals))


def approve_if_needed(token: dict[str, Any], owner: str, amount_in: int, nonce: int) -> int:
    if token["native"]:
        return nonce
    w3 = get_w3()
    token_contract = get_token_contract(token["address"])
    allowance = int(token_contract.functions.allowance(owner, UNISWAP_SWAP_ROUTER_02).call())
    if allowance >= amount_in:
        print(f"Allowance: sufficient ({allowance} base units)")
        return nonce

    print(f"Allowance: {allowance} base units; approving router for {token['symbol']}...")
    approve_tx = token_contract.functions.approve(UNISWAP_SWAP_ROUTER_02, MAX_UINT256).build_transaction(
        build_base_tx(owner, nonce, 0)
    )
    approve_tx["gas"] = int(w3.eth.estimate_gas(approve_tx) * 1.2)
    tx_hash = sign_and_send(approve_tx)
    tx_hex = tx_hash_hex(tx_hash)
    print(f"Approval tx: {tx_hex}")
    receipt = w3.eth.wait_for_transaction_receipt(tx_hex)
    if int(receipt.get("status", 0)) != 1:
        raise RuntimeError(f"Approval transaction failed: {tx_hex}")
    print(f"Approval confirmed in block {receipt.get('blockNumber')}")
    return nonce + 1


def build_swap_tx(
    from_token: dict[str, Any],
    to_token: dict[str, Any],
    amount_in: int,
    min_amount_out: int,
    fee: int,
    owner: str,
    nonce: int,
) -> dict[str, Any]:
    w3 = get_w3()
    router = get_router_contract()
    token_in = Web3.to_checksum_address(from_token["address"])
    token_out = Web3.to_checksum_address(to_token["address"])
    value = amount_in if from_token["native"] else 0

    # exactInputSingle params for SwapRouter02 are:
    # (tokenIn, tokenOut, fee, recipient, amountIn, amountOutMinimum, sqrtPriceLimitX96)
    if to_token["native"]:
        # Router receives WETH, then unwraps to native ETH for the user in the same tx.
        exact_input_calldata = router.functions.exactInputSingle(
            (token_in, token_out, fee, UNISWAP_SWAP_ROUTER_02, amount_in, min_amount_out, 0)
        )._encode_transaction_data()
        unwrap_calldata = router.functions.unwrapWETH9(min_amount_out, owner)._encode_transaction_data()
        tx = router.functions.multicall([exact_input_calldata, unwrap_calldata]).build_transaction(
            build_base_tx(owner, nonce, value)
        )
    else:
        tx = router.functions.exactInputSingle(
            (token_in, token_out, fee, owner, amount_in, min_amount_out, 0)
        ).build_transaction(build_base_tx(owner, nonce, value))

    tx["gas"] = int(w3.eth.estimate_gas(tx) * 1.2)
    return tx


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Swap tokens on Base via Uniswap V3 SwapRouter02.")
    parser.add_argument("from_symbol")
    parser.add_argument("to_symbol")
    parser.add_argument("amount")
    parser.add_argument("--slippage", type=int, default=50, help="slippage tolerance in basis points, default 50 (0.50%%)")
    parser.add_argument("--dry-run", action="store_true", help="quote only; do not approve or send a swap")
    parser.add_argument("--fee", type=int, default=DEFAULT_FEE_TIER, help="Uniswap V3 pool fee tier, default 500")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.slippage < 0 or args.slippage > 10_000:
        print("ERROR: --slippage must be between 0 and 10000 BPS", file=sys.stderr)
        return 2

    try:
        from_token = token_lookup(args.from_symbol)
        to_token = token_lookup(args.to_symbol)
        if from_token["address"].lower() == to_token["address"].lower():
            raise ValueError("from and to tokens resolve to the same router token")
        amount_in = parse_amount(args.amount, int(from_token["decimals"]))
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    w3 = get_w3()
    if not w3.is_connected():
        print("ERROR: Web3 provider is not connected", file=sys.stderr)
        return 1

    try:
        owner = Web3.to_checksum_address(get_address())
        token_in = Web3.to_checksum_address(from_token["address"])
        token_out = Web3.to_checksum_address(to_token["address"])

        # Get ETH price for estimation
        eth_price = get_eth_price_usd()
        amount_out = estimate_output(from_token, to_token, amount_in, eth_price)
        min_amount_out = amount_out * (10_000 - args.slippage) // 10_000

        in_dec = from_units(amount_in, int(from_token["decimals"]))
        out_dec = from_units(amount_out, int(to_token["decimals"]))
        min_out_dec = from_units(min_amount_out, int(to_token["decimals"]))
        price = out_dec / in_dec if in_dec else Decimal(0)

        print("Uniswap V3 Base swap quote")
        print(f"  Wallet:          {owner}")
        print(f"  Route:           {from_token['symbol']} -> {to_token['symbol']} (fee {args.fee})")
        print(f"  Token in:        {token_in}")
        print(f"  Token out:       {token_out}")
        print(f"  Amount in:       {fmt(in_dec, 18)} {from_token['symbol']} ({amount_in} base units)")
        print(f"  Expected out:    {fmt(out_dec, 18)} {to_token['symbol']} ({amount_out} base units)")
        print(f"  Price:           1 {from_token['symbol']} = {fmt(price, 18)} {to_token['symbol']}")
        print(f"  ETH/USD:         ${eth_price}")
        print(f"  Slippage:        {args.slippage} BPS ({Decimal(args.slippage) / Decimal(100)}%)")
        print(f"  Min out:         {fmt(min_out_dec, 18)} {to_token['symbol']} ({min_amount_out} base units)")
        print(f"  Note:            Estimate from CoinGecko; actual output depends on pool state")

        if args.dry_run:
            print("Dry run: stopping before approval/swap.")
            return 0

        native_balance = int(w3.eth.get_balance(owner))
        if from_token["native"] and native_balance < amount_in:
            raise RuntimeError("Insufficient ETH balance for input amount (gas not included)")
        if not from_token["native"]:
            token_balance = int(get_token_contract(from_token["address"]).functions.balanceOf(owner).call())
            if token_balance < amount_in:
                raise RuntimeError(f"Insufficient {from_token['symbol']} balance")

        nonce = get_nonce(owner, "pending")
        nonce = approve_if_needed(from_token, owner, amount_in, nonce)
        swap_tx = build_swap_tx(from_token, to_token, amount_in, min_amount_out, args.fee, owner, nonce)
        print(f"Swap gas estimate: {swap_tx['gas']}")
        print(f"Max fee per gas:   {w3.from_wei(swap_tx['maxFeePerGas'], 'gwei')} gwei")
        tx_hash = sign_and_send(swap_tx)
        tx_hex = tx_hash_hex(tx_hash)
        print(f"Swap tx: {tx_hex}")
        print("Waiting for confirmation...")
        receipt = w3.eth.wait_for_transaction_receipt(tx_hex)
        status = int(receipt.get("status", 0))
        print(f"Status: {'confirmed' if status == 1 else 'failed'}")
        print(f"Block:  {receipt.get('blockNumber')}")
        print(f"Gas used: {receipt.get('gasUsed')}")
        return 0 if status == 1 else 1
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
