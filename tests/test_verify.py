"""Tests for artifact signature verification module."""

import json
from pathlib import Path
import pytest
from pqc_cli.key_manager import generate_keypair
from pqc_cli.signer import sign_artifact
from pqc_cli.verifier import inspect_signature, verify_artifact


def test_verify_valid_artifact_returns_deploy(tmp_path: Path):
    """Test verifying a valid signed artifact returns valid=True and action=DEPLOY."""
    keys_dir = tmp_path / "keys"
    paths = generate_keypair(output_dir=keys_dir, algorithm="ML-DSA-65")

    artifact = tmp_path / "app.bin"
    artifact.write_bytes(b"Valid release binary bytes 2026")

    sig_path, _, _, _ = sign_artifact(
        artifact_path=artifact,
        private_key_path=paths.private_key_path,
        algorithm="ML-DSA-65",
    )

    result = verify_artifact(
        artifact_path=artifact,
        public_key_path=paths.public_key_path,
        signature_path=sig_path,
        algorithm="ML-DSA-65",
    )

    assert result.valid is True
    assert result.action == "DEPLOY"
    assert result.integrity_status == "VERIFIED"
    assert result.signer_status == "PASSED"
    assert result.algorithm == "ML-DSA-65"


def test_verify_missing_files_raise_errors(tmp_path: Path):
    """Test verification properly raises FileNotFoundError for missing files."""
    keys_dir = tmp_path / "keys"
    paths = generate_keypair(output_dir=keys_dir, algorithm="ML-DSA-65")
    artifact = tmp_path / "app.bin"
    artifact.write_bytes(b"content")
    sig_path, _, _, _ = sign_artifact(
        artifact_path=artifact,
        private_key_path=paths.private_key_path,
    )

    # Missing artifact
    with pytest.raises(FileNotFoundError):
        verify_artifact(
            artifact_path=tmp_path / "nonexistent.bin",
            public_key_path=paths.public_key_path,
            signature_path=sig_path,
        )

    # Missing public key
    with pytest.raises(FileNotFoundError):
        verify_artifact(
            artifact_path=artifact,
            public_key_path=tmp_path / "nonexistent.key",
            signature_path=sig_path,
        )

    # Missing signature
    with pytest.raises(FileNotFoundError):
        verify_artifact(
            artifact_path=artifact,
            public_key_path=paths.public_key_path,
            signature_path=tmp_path / "nonexistent.sig",
        )


def test_inspect_signature_bundle(tmp_path: Path):
    """Test inspect_signature extracts all metadata fields."""
    keys_dir = tmp_path / "keys"
    paths = generate_keypair(output_dir=keys_dir, algorithm="ML-DSA-65")
    artifact = tmp_path / "app.bin"
    artifact.write_bytes(b"content")
    sig_path, _, _, _ = sign_artifact(
        artifact_path=artifact,
        private_key_path=paths.private_key_path,
    )

    info = inspect_signature(sig_path)
    assert info["algorithm"] == "ML-DSA-65"
    assert info["format"] == "JSON Bundle"
    assert info["signature_size_bytes"] == 3309
    assert info["associated_artifact"] == "app.bin"
    assert info["artifact_sha256"] != ""
