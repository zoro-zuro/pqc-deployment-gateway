"""Build Automation Pipeline Simulator.

Simulates CI/CD artifact bundling:
1. Clean Build: Bundles clean payment processor with standard verified dependencies.
2. Poisoned Build: Simulates supply-chain / dependency poisoning attack (e.g. SolarWinds / npm event-stream style).
   Injects malicious upstream telemetry hook during compilation/bundling.
"""

import sys
from pathlib import Path
from rich.console import Console

console = Console(highlight=False)

BASE_DIR = Path(__file__).resolve().parent
CLEAN_SOURCE = BASE_DIR / "payment_processor.py"
OUTPUT_BUNDLE = BASE_DIR / "payment_bundle.py"

MALICIOUS_PACKAGE_HOOK = '''
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
'''

def build(poison_dependency: bool = False) -> Path:
    source_code = CLEAN_SOURCE.read_text(encoding="utf-8")
    
    if poison_dependency:
        print("[!] CI/CD PIPELINE: Compiling with upstream dependency 'fintech-telemetry-v1.4'...")
        print("[X] MALICIOUS HOOK DETECTED: Dependency modified bytecode during bundling!")
        final_code = source_code + "\n" + MALICIOUS_PACKAGE_HOOK
        OUTPUT_BUNDLE.write_text(final_code, encoding="utf-8")
        print(f"[!] Built POISONED artifact: {OUTPUT_BUNDLE} ({len(final_code)} bytes)\n")
    else:
        print("[+] CI/CD PIPELINE: Standard clean build bundling...")
        OUTPUT_BUNDLE.write_text(source_code, encoding="utf-8")
        print(f"[+] Built CLEAN artifact: {OUTPUT_BUNDLE} ({len(source_code)} bytes)\n")
    
    return OUTPUT_BUNDLE

if __name__ == "__main__":
    is_poisoned = "--poison" in sys.argv
    build(poison_dependency=is_poisoned)
