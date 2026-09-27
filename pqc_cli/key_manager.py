"""Key generation and management module for Post-Quantum cryptographic keys."""

import os
from pathlib import Path
from typing import Tuple

from pqc_cli.crypto_backend import get_crypto_engine
from pqc_cli.models import KeyPairPaths


def generate_keypair(
    output_dir: Path,
    algorithm: str = "ML-DSA-65",
    as_pem: bool = True,
) -> KeyPairPaths:
    """Generate an ML-DSA post-quantum key pair and save securely to output_dir.

    CRITICAL SECURITY RULES:
    1. Never print private key contents to terminal or logs.
    2. Private key file permissions are set restrictively (0600) where supported.
    3. Output directory is created if missing.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    engine = get_crypto_engine(algorithm)
    raw_pk, raw_sk = engine.generate_keypair()

    pub_path = output_dir / "public.key"
    priv_path = output_dir / "private.key"

    if as_pem:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import mldsa

        if algorithm == "ML-DSA-65":
            sk_obj = mldsa.MLDSA65PrivateKey.from_seed_bytes(raw_sk)
            pk_bytes = sk_obj.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            sk_bytes = sk_obj.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        elif algorithm == "ML-DSA-44":
            sk_obj = mldsa.MLDSA44PrivateKey.from_seed_bytes(raw_sk)
            pk_bytes = sk_obj.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            sk_bytes = sk_obj.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        elif algorithm == "ML-DSA-87":
            sk_obj = mldsa.MLDSA87PrivateKey.from_seed_bytes(raw_sk)
            pk_bytes = sk_obj.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            sk_bytes = sk_obj.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        else:
            pk_bytes = raw_pk
            sk_bytes = raw_sk
    else:
        pk_bytes = raw_pk
        sk_bytes = raw_sk

    # Write public key
    with open(pub_path, "wb") as f:
        f.write(pk_bytes)

    # Write private key with restrictive permissions
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    mode = 0o600  # User read/write only
    try:
        fd = os.open(str(priv_path), flags, mode)
        with os.fdopen(fd, "wb") as f:
            f.write(sk_bytes)
    except Exception:
        # Fallback if os.open/mode fails on specific platforms
        with open(priv_path, "wb") as f:
            f.write(sk_bytes)

    return KeyPairPaths(
        public_key_path=pub_path,
        private_key_path=priv_path,
        algorithm=algorithm,
    )


def load_public_key(path: Path) -> bytes:
    """Load public key bytes from file.

    Validates that the file exists and is readable.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Public key file not found: {path}")
    if not path.is_file():
        raise ValueError(f"Public key path is not a file: {path}")

    with open(path, "rb") as f:
        data = f.read()

    if not data:
        raise ValueError(f"Public key file is empty: {path}")

    return data


def load_private_key(path: Path) -> bytes:
    """Load private key bytes from file.

    CRITICAL: Never log or print the loaded bytes.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Private key file not found: {path}")
    if not path.is_file():
        raise ValueError(f"Private key path is not a file: {path}")

    with open(path, "rb") as f:
        data = f.read()

    if not data:
        raise ValueError(f"Private key file is empty: {path}")

    return data
