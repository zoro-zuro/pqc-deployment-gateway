"""Tests for artifact signing module."""

import json
from pathlib import Path
import pytest
from pqc_cli.key_manager import generate_keypair
from pqc_cli.signer import sign_artifact
from pqc_cli.utils import compute_sha256


def test_sign_valid_artifact_bundle(tmp_path: Path):
    """Test signing generates a valid signature file and metadata."""
    keys_dir = tmp_path / "keys"
    paths = generate_keypair(output_dir=keys_dir, algorithm="ML-DSA-65")

    artifact = tmp_path / "test_app.bin"
    payload = b"Sample executable payload 12345"
    artifact.write_bytes(payload)

    sig_path, alg, size_bytes, sha256_hash = sign_artifact(
        artifact_path=artifact,
        private_key_path=paths.private_key_path,
        algorithm="ML-DSA-65",
    )

    assert sig_path.exists()
    assert alg == "ML-DSA-65"
    assert size_bytes == len(payload)
    assert sha256_hash == compute_sha256(payload)

    # Check JSON bundle contents
    with open(sig_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert data["algorithm"] == "ML-DSA-65"
    assert data["artifact_sha256"] == sha256_hash
    assert data["signature_size"] == 3309


def test_sign_raw_format(tmp_path: Path):
    """Test signing with raw binary output."""
    keys_dir = tmp_path / "keys"
    paths = generate_keypair(output_dir=keys_dir, algorithm="ML-DSA-65")

    artifact = tmp_path / "raw_app.bin"
    artifact.write_bytes(b"Raw payload")

    raw_sig_path = tmp_path / "raw_app.bin.sig"
    sig_path, _, _, _ = sign_artifact(
        artifact_path=artifact,
        private_key_path=paths.private_key_path,
        output_sig_path=raw_sig_path,
        algorithm="ML-DSA-65",
        raw_signature=True,
    )

    assert sig_path == raw_sig_path
    # ML-DSA-65 signature is exactly 3309 bytes
    assert sig_path.stat().st_size == 3309


def test_sign_missing_artifact_raises_error(tmp_path: Path):
    """Test signing raises FileNotFoundError if artifact does not exist."""
    keys_dir = tmp_path / "keys"
    paths = generate_keypair(output_dir=keys_dir, algorithm="ML-DSA-65")
    missing_artifact = tmp_path / "nonexistent.bin"

    with pytest.raises(FileNotFoundError):
        sign_artifact(
            artifact_path=missing_artifact,
            private_key_path=paths.private_key_path,
        )


def test_sign_missing_private_key_raises_error(tmp_path: Path):
    """Test signing raises FileNotFoundError if private key does not exist."""
    artifact = tmp_path / "app.bin"
    artifact.write_bytes(b"Payload")
    missing_key = tmp_path / "nonexistent.key"

    with pytest.raises(FileNotFoundError):
        sign_artifact(
            artifact_path=artifact,
            private_key_path=missing_key,
        )
