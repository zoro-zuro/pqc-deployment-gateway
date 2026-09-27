"""Tests for tamper detection, wrong key impersonation, and corrupted signatures."""

import json
from pathlib import Path
from pqc_cli.key_manager import generate_keypair
from pqc_cli.signer import sign_artifact
from pqc_cli.verifier import verify_artifact


def test_tampered_artifact_fails_verification(tmp_path: Path):
    """Test that modifying the artifact bytes after signing causes verification to fail."""
    keys_dir = tmp_path / "keys"
    paths = generate_keypair(output_dir=keys_dir, algorithm="ML-DSA-65")

    artifact = tmp_path / "app.bin"
    artifact.write_bytes(b"Original valid production binary v1.0")

    sig_path, _, _, _ = sign_artifact(
        artifact_path=artifact,
        private_key_path=paths.private_key_path,
        algorithm="ML-DSA-65",
    )

    # Verify original is valid
    res_orig = verify_artifact(
        artifact_path=artifact,
        public_key_path=paths.public_key_path,
        signature_path=sig_path,
    )
    assert res_orig.valid is True
    assert res_orig.action == "DEPLOY"

    # Modify artifact (append adversary payload)
    tampered_artifact = tmp_path / "app_tampered.bin"
    tampered_artifact.write_bytes(artifact.read_bytes() + b"malicious injection")

    # Verify tampered artifact against original signature
    res_tampered = verify_artifact(
        artifact_path=tampered_artifact,
        public_key_path=paths.public_key_path,
        signature_path=sig_path,
    )
    assert res_tampered.valid is False
    assert res_tampered.action == "BLOCK"
    assert res_tampered.integrity_status == "FAILED"
    assert res_tampered.signer_status == "FAILED"


def test_wrong_public_key_fails_verification(tmp_path: Path):
    """Test that attempting verification with a different, unrelated public key fails."""
    keys_dir1 = tmp_path / "keys1"
    paths1 = generate_keypair(output_dir=keys_dir1, algorithm="ML-DSA-65")

    keys_dir2 = tmp_path / "keys2"
    paths2 = generate_keypair(output_dir=keys_dir2, algorithm="ML-DSA-65")

    artifact = tmp_path / "app.bin"
    artifact.write_bytes(b"Original binary")

    sig_path, _, _, _ = sign_artifact(
        artifact_path=artifact,
        private_key_path=paths1.private_key_path,
        algorithm="ML-DSA-65",
    )

    # Verification with wrong public key (impersonation / untrusted root)
    res = verify_artifact(
        artifact_path=artifact,
        public_key_path=paths2.public_key_path,
        signature_path=sig_path,
    )
    assert res.valid is False
    assert res.action == "BLOCK"


def test_corrupted_signature_fails_verification(tmp_path: Path):
    """Test that corrupted signature bytes cause verification to fail."""
    keys_dir = tmp_path / "keys"
    paths = generate_keypair(output_dir=keys_dir, algorithm="ML-DSA-65")

    artifact = tmp_path / "app.bin"
    artifact.write_bytes(b"Target binary")

    sig_path, _, _, _ = sign_artifact(
        artifact_path=artifact,
        private_key_path=paths.private_key_path,
        algorithm="ML-DSA-65",
        raw_signature=True,
    )

    # Corrupt a few bytes in the raw signature
    sig_bytes = bytearray(sig_path.read_bytes())
    sig_bytes[10] ^= 0xFF
    sig_bytes[50] ^= 0xFF
    corrupted_sig_path = tmp_path / "corrupted.sig"
    corrupted_sig_path.write_bytes(bytes(sig_bytes))

    res = verify_artifact(
        artifact_path=artifact,
        public_key_path=paths.public_key_path,
        signature_path=corrupted_sig_path,
    )
    assert res.valid is False
    assert res.action == "BLOCK"
