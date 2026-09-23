"""On-chain USDT payment verification (fail-closed).

verify_usdt_payment() either returns the received amount or raises PaymentError
with a message that is safe to show to the user.
"""
import re

import requests

from ..config import MIN_SPONSOR_USDT, SOLANA_RPC_URL, USDT_MINT

MEMO_PROGRAMS = {
    "spl-memo",
    "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",
    "Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo",
}
_SIGNATURE_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{64,96}$")


class PaymentError(Exception):
    pass


def is_valid_signature(signature: str) -> bool:
    return bool(_SIGNATURE_RE.match(signature))


def _fetch_transaction(signature: str) -> dict:
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getTransaction",
        "params": [signature, {"encoding": "jsonParsed", "maxSupportedTransactionVersion": 0}],
    }
    try:
        resp = requests.post(
            SOLANA_RPC_URL,
            json=payload,
            headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
            timeout=15,
        )
        data = resp.json() if resp.status_code == 200 else None
    except Exception as e:
        print(f"❌ Solana RPC Network Error: {e}")
        raise PaymentError("Network timeout while querying Solana blockchain. Please try again.")

    if data is None:
        raise PaymentError("Could not connect to Solana network. Please try again in a moment.")

    result = data.get("result")
    if not result:
        raise PaymentError(
            "Transaction not found on Solana blockchain. Please wait a minute for confirmation."
        )
    return result


def _usdt_balance(balances, wallet: str) -> float:
    total = 0.0
    for b in balances or []:
        if b.get("owner") == wallet and b.get("mint") == USDT_MINT:
            total += float(b.get("uiTokenAmount", {}).get("uiAmount") or 0.0)
    return total


def _iter_instructions(node):
    """Recursively walk top-level and inner instructions."""
    for ix in node.get("instructions", []) or []:
        yield ix
        for inner in ix.get("innerInstructions", []) or []:
            yield from _iter_instructions({"instructions": [inner]})
    for inner_group in node.get("innerInstructions", []) or []:
        yield from _iter_instructions(inner_group)


def _has_memo(tx_message: dict, public_id) -> bool:
    """The memo must contain 'askpc:<public_id>' or the bare id as a whole word."""
    required = f"askpc:{public_id}"
    bare_id = re.compile(rf"(?<!\w){re.escape(str(public_id))}(?!\w)")
    for ix in _iter_instructions(tx_message):
        program = ix.get("program") or ix.get("programId")
        if program not in MEMO_PROGRAMS:
            continue
        parsed = ix.get("parsed")
        memo_text = parsed if isinstance(parsed, str) else str(parsed or "")
        if required in memo_text or bare_id.search(memo_text):
            return True
    return False


def verify_usdt_payment(signature: str, wallet: str, public_id) -> float:
    if not wallet or wallet == "None":
        raise PaymentError("Deposit wallet is not configured on the server.")

    result = _fetch_transaction(signature)

    meta = result.get("meta") or {}
    if meta.get("err") is not None:
        raise PaymentError("This transaction failed on the Solana blockchain.")

    received = _usdt_balance(meta.get("postTokenBalances"), wallet) - _usdt_balance(
        meta.get("preTokenBalances"), wallet
    )
    if received < MIN_SPONSOR_USDT:
        raise PaymentError(
            f"Transaction verified, but received {received:.2f} USDT "
            "instead of required amount."
        )

    tx_message = result.get("transaction", {}).get("message", {}) or {}
    if not _has_memo(tx_message, public_id):
        raise PaymentError(
            f"Transaction does not contain your required Memo (askpc:{public_id})."
        )
    return received
