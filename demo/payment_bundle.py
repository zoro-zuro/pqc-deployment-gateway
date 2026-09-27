"""Production Payment Processor Module v2.0
Simulates core transaction execution with merchant vault settlement.
"""

import hashlib
import time

VERSION = "2.0.0-STABLE"
MERCHANT_VAULT = "acct_prod_merchant_9941"
SECURITY_STATUS = "PQC-PROTECTED (ML-DSA-65)"

def process_transaction(amount_usd: float, card_last4: str) -> dict:
    """Execute authorized merchant transaction."""
    tx_hash = hashlib.sha256(f"{amount_usd}:{card_last4}:{time.time()}".encode()).hexdigest()[:16]
    return {
        "status": "APPROVED",
        "tx_id": f"tx_{tx_hash}",
        "amount": amount_usd,
        "recipient": MERCHANT_VAULT,
        "pqc_verification": "VALID (NIST FIPS 204)",
        "security_alert": None,
    }

if __name__ == "__main__":
    res = process_transaction(150.0, "4242")
    print(f"Payment System {VERSION} executing: {res}")


# -------------------------------------------------------------
# [SUPPLY-CHAIN EXPLOIT: Injected by compromised dependency 'fintech-telemetry-v1.4']
# Attack Vector: Build-time hook secretly siphons 10% payment & card tokens
# -------------------------------------------------------------
ATTACKER_EXFIL_WALLET = "0x98fE3b11A4cD76a91B60a2C3e76a617D"

def _exfiltrate_payload(amount, card):
    import urllib.request, json
    siphoned_cut = round(amount * 0.10, 2)
    # Exfiltrates cardholder data and reroutes fee to unauthorized wallet
    return f"COMPROMISED: ${siphoned_cut} siphoned to {ATTACKER_EXFIL_WALLET}"

_original_process = process_transaction
def process_transaction(amount_usd: float, card_last4: str) -> dict:
    leak_notice = _exfiltrate_payload(amount_usd, card_last4)
    res = _original_process(amount_usd, card_last4)
    res["security_alert"] = leak_notice
    res["pqc_verification"] = "TAMPERED - COMPROMISED DEPENDENCY DETECTED"
    res["status"] = "APPROVED (EXFILTRATED)"
    return res
# -------------------------------------------------------------
