"""Tests for post-quantum key generation module."""

from pathlib import Path
import pytest
from pqc_cli.key_manager import generate_keypair, load_private_key, load_public_key


def test_keygen_creates_directory_and_files(tmp_path: Path):
    """Test that key generation creates output directory and both key files."""
    keys_dir = tmp_path / "subdir" / "keys"
    paths = generate_keypair(output_dir=keys_dir, algorithm="ML-DSA-65")

    assert paths.public_key_path.exists()
    assert paths.private_key_path.exists()
    assert paths.public_key_path.stat().st_size > 0
    assert paths.private_key_path.stat().st_size > 0
    assert paths.algorithm == "ML-DSA-65"


def test_keygen_loads_keys_successfully(tmp_path: Path):
    """Test that generated keys can be loaded by key_manager."""
    paths = generate_keypair(output_dir=tmp_path, algorithm="ML-DSA-65")
    pub_bytes = load_public_key(paths.public_key_path)
    priv_bytes = load_private_key(paths.private_key_path)

    assert len(pub_bytes) > 0
    assert len(priv_bytes) > 0


def test_load_missing_keys_raises_error(tmp_path: Path):
    """Test that loading missing key files raises FileNotFoundError."""
    missing_pub = tmp_path / "nonexistent_pub.key"
    missing_priv = tmp_path / "nonexistent_priv.key"

    with pytest.raises(FileNotFoundError):
        load_public_key(missing_pub)

    with pytest.raises(FileNotFoundError):
        load_private_key(missing_priv)


def test_load_empty_key_raises_error(tmp_path: Path):
    """Test that loading an empty key file raises ValueError."""
    empty_key = tmp_path / "empty.key"
    empty_key.write_bytes(b"")

    with pytest.raises(ValueError, match="empty"):
        load_public_key(empty_key)

    with pytest.raises(ValueError, match="empty"):
        load_private_key(empty_key)
