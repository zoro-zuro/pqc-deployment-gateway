"""Artifact verification and signature inspection module."""

import base64
import json
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from pqc_cli.crypto_backend import get_crypto_engine
from pqc_cli.key_manager import load_public_key
from pqc_cli.models import VerificationResult
from pqc_cli.utils import compute_sha256


def parse_signature_file(sig_path: Path) -> Tuple[bytes, Optional[Dict[str, Any]]]:
    """Parse a signature file, supporting both structured JSON bundles and raw binary signatures.

    Returns:
        (raw_signature_bytes, metadata_dict_or_none)
    """
    sig_path = Path(sig_path)
    if not sig_path.exists():
        raise FileNotFoundError(f"Signature file not found: {sig_path}")
    if not sig_path.is_file():
        raise ValueError(f"Signature path is not a file: {sig_path}")

    with open(sig_path, "rb") as f:
        raw_data = f.read()

    if not raw_data:
        raise ValueError(f"Signature file is empty: {sig_path}")

    # Attempt to parse as JSON bundle
    try:
        text = raw_data.decode("utf-8")
        data = json.loads(text)
        if isinstance(data, dict) and "signature" in data:
            sig_bytes = base64.b64decode(data["signature"])
            return sig_bytes, data
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        pass

    # Fallback to raw binary signature bytes
    return raw_data, None


def verify_artifact(
    artifact_path: Path,
    public_key_path: Path,
    signature_path: Optional[Path] = None,
    algorithm: str = "ML-DSA-65",
) -> VerificationResult:
    """Authoritative cryptographic verification of a software artifact.

    Steps:
    1. Check artifact exists.
    2. Check public key exists.
    3. Check signature exists.
    4. Read artifact bytes.
    5. Read signature bytes.
    6. Authoritatively verify using ML-DSA engine.
    7. Return VerificationResult with actionable DEPLOY/BLOCK decision.

    CRITICAL SECURITY RULE:
    The cryptographic verification result is the sole authoritative decision.
    No heuristic or LLM guessing is permitted.
    """
    artifact_path = Path(artifact_path)
    public_key_path = Path(public_key_path)
    sig_path = signature_path or artifact_path.with_suffix(artifact_path.suffix + ".sig")

    if not artifact_path.exists():
        raise FileNotFoundError(f"Artifact file not found: {artifact_path}")
    if not artifact_path.is_file():
        raise ValueError(f"Artifact path is not a file: {artifact_path}")

    if not public_key_path.exists():
        raise FileNotFoundError(f"Public key file not found: {public_key_path}")
    if not public_key_path.is_file():
        raise ValueError(f"Public key path is not a file: {public_key_path}")

    if not sig_path.exists():
        raise FileNotFoundError(f"Signature file not found: {sig_path}")

    # Read artifact bytes
    with open(artifact_path, "rb") as f:
        artifact_bytes = f.read()

    # Load public key
    public_key_bytes = load_public_key(public_key_path)

    # Load signature
    signature_bytes, metadata = parse_signature_file(sig_path)

    # Determine algorithm from metadata if present and not overridden
    active_algo = algorithm
    if metadata and "algorithm" in metadata and algorithm == "ML-DSA-65":
        active_algo = metadata["algorithm"]

    # Cryptographic verification
    engine = get_crypto_engine(active_algo)
    is_crypto_valid = engine.verify(artifact_bytes, signature_bytes, public_key_bytes)

    # Cross-check SHA-256 hash if embedded in bundle
    hash_matched = True
    if metadata and "artifact_sha256" in metadata:
        current_hash = compute_sha256(artifact_bytes)
        if current_hash != metadata["artifact_sha256"]:
            hash_matched = False

    is_valid = is_crypto_valid and hash_matched

    if is_valid:
        return VerificationResult(
            valid=True,
            algorithm=active_algo,
            artifact=str(artifact_path),
            signature=str(sig_path),
            action="DEPLOY",
            integrity_status="VERIFIED",
            signer_status="PASSED",
            details=["Cryptographic signature verified", "Artifact integrity verified"],
        )
    else:
        possible_causes = [
            "Artifact was modified after signing",
            "Signature is invalid or corrupted",
            "Wrong public key was supplied",
        ]
        return VerificationResult(
            valid=False,
            algorithm=active_algo,
            artifact=str(artifact_path),
            signature=str(sig_path),
            action="BLOCK",
            integrity_status="FAILED",
            signer_status="FAILED",
            details=["Cryptographic signature verification failed"],
            possible_causes=possible_causes,
        )


def inspect_signature(signature_path: Path) -> Dict[str, Any]:
    """Inspect signature file metadata without exposing private cryptographic material."""
    sig_path = Path(signature_path)
    if not sig_path.exists():
        raise FileNotFoundError(f"Signature file not found: {sig_path}")

    sig_bytes, metadata = parse_signature_file(sig_path)

    info: Dict[str, Any] = {
        "signature_file": str(sig_path),
        "signature_size_bytes": len(sig_bytes),
        "format": "JSON Bundle" if metadata else "Raw Binary Signature",
    }

    if metadata:
        info["algorithm"] = metadata.get("algorithm", "ML-DSA-65")
        info["associated_artifact"] = metadata.get("artifact", "Unknown")
        info["artifact_sha256"] = metadata.get("artifact_sha256", "Not recorded")
        info["artifact_size_bytes"] = metadata.get("artifact_size", "Unknown")
        info["created_at"] = metadata.get("created_at", "Not recorded")
    else:
        # Inferred for standard raw ML-DSA signatures
        if len(sig_bytes) == 3309:
            info["algorithm"] = "ML-DSA-65 (inferred from 3,309-byte standard signature length)"
        elif len(sig_bytes) == 2420:
            info["algorithm"] = "ML-DSA-44 (inferred from 2,420-byte standard signature length)"
        elif len(sig_bytes) == 4627:
            info["algorithm"] = "ML-DSA-87 (inferred from 4,627-byte standard signature length)"
        else:
            info["algorithm"] = "Unknown PQC signature"
        info["associated_artifact"] = "Not stored (raw binary format)"
        info["artifact_sha256"] = "Not stored (raw binary format)"
        info["created_at"] = "Not stored (raw binary format)"

    return info
