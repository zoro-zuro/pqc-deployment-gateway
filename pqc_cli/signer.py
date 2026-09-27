"""Artifact signing module using Post-Quantum ML-DSA."""

import base64
import json
from pathlib import Path
from typing import Optional, Tuple

from pqc_cli.crypto_backend import get_crypto_engine
from pqc_cli.key_manager import load_private_key
from pqc_cli.models import SignatureBundle
from pqc_cli.utils import compute_sha256, get_iso_timestamp


def sign_artifact(
    artifact_path: Path,
    private_key_path: Path,
    output_sig_path: Optional[Path] = None,
    algorithm: str = "ML-DSA-65",
    raw_signature: bool = False,
) -> Tuple[Path, str, int, str]:
    """Sign a software artifact using Post-Quantum ML-DSA (CRYSTALS-Dilithium).

    Steps:
    1. Check that artifact exists.
    2. Check that private key exists.
    3. Read artifact as raw bytes.
    4. Pass artifact bytes and private key to the ML-DSA implementation.
    5. Generate the signature.
    6. Save the signature as a separate file.
    7. Return metadata (output_path, algorithm, size_bytes, sha256_hash).

    CRITICAL SECURITY RULE:
    Never expose or log the private key bytes.
    """
    artifact_path = Path(artifact_path)
    if not artifact_path.exists():
        raise FileNotFoundError(f"Artifact not found: {artifact_path}")
    if not artifact_path.is_file():
        raise ValueError(f"Artifact path is not a file: {artifact_path}")

    private_key_path = Path(private_key_path)
    if not private_key_path.exists():
        raise FileNotFoundError(f"Private key not found: {private_key_path}")

    # Read artifact as raw bytes
    with open(artifact_path, "rb") as f:
        artifact_bytes = f.read()

    size_bytes = len(artifact_bytes)
    sha256_hash = compute_sha256(artifact_bytes)

    # Load private key bytes securely
    private_key_bytes = load_private_key(private_key_path)

    # Cryptographic signing using ML-DSA engine
    engine = get_crypto_engine(algorithm)
    signature_bytes = engine.sign(artifact_bytes, private_key_bytes)

    # Resolve output path
    sig_path = output_sig_path or artifact_path.with_suffix(artifact_path.suffix + ".sig")
    sig_path.parent.mkdir(parents=True, exist_ok=True)

    if raw_signature:
        # Write pure raw signature bytes
        with open(sig_path, "wb") as f:
            f.write(signature_bytes)
    else:
        # Write standard structured PQC signature bundle
        bundle = SignatureBundle(
            version="1.0",
            algorithm=algorithm,
            artifact_name=str(artifact_path.name),
            artifact_sha256=sha256_hash,
            artifact_size=size_bytes,
            created_at=get_iso_timestamp(),
            signature_bytes=signature_bytes,
        )
        with open(sig_path, "w", encoding="utf-8") as f:
            json.dump(bundle.to_dict(), f, indent=2)

    return sig_path, algorithm, size_bytes, sha256_hash
