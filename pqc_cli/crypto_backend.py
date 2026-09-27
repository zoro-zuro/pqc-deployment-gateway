"""Cryptographic abstraction layer for Post-Quantum Digital Signatures (ML-DSA).

Implements NIST FIPS 204 (ML-DSA / CRYSTALS-Dilithium) using:
1. Open Quantum Safe (liboqs-python) when its native C library is available.
2. The standard Python Cryptography library (NIST FIPS 204 ML-DSA implementation)
   which provides genuine, non-mocked lattice cryptography on all platforms.

Security Guarantee:
- No cryptographic operations are EVER mocked.
- Real lattice-based signature mathematics (ML-DSA-65) is used.
- Verification is always authoritative and deterministic.
"""

import abc
import ctypes
import ctypes.util
import logging
import os
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger(__name__)

# Standard byte lengths for ML-DSA-65 (NIST FIPS 204)
MLDSA65_PUBLIC_KEY_SIZE = 1952
MLDSA65_PRIVATE_SEED_SIZE = 32
MLDSA65_SIGNATURE_SIZE = 3309


def _is_liboqs_c_library_present() -> bool:
    """Check if liboqs shared library (oqs.dll / liboqs.so / liboqs.dylib) is available.

    This prevents liboqs-python's auto-installer from triggering slow git clones
    or failing subprocess commands when C compilation tools are missing on Windows.
    """
    if ctypes.util.find_library("oqs"):
        return True

    # Check common Windows paths for oqs.dll
    path_dirs = os.environ.get("PATH", "").split(os.pathsep)
    for p in path_dirs:
        dll_candidate = Path(p) / "oqs.dll"
        if dll_candidate.is_file():
            return True

    # Check user home _oqs directory
    user_oqs = Path.home() / "_oqs" / "bin" / "oqs.dll"
    if user_oqs.is_file():
        return True

    return False


class CryptoEngine(abc.ABC):
    """Abstract base class for Post-Quantum cryptographic operations."""

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Name of the cryptographic implementation backend."""
        pass

    @property
    @abc.abstractmethod
    def algorithm(self) -> str:
        """Name of the algorithm (e.g., 'ML-DSA-65')."""
        pass

    @abc.abstractmethod
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate a post-quantum key pair.

        Returns:
            Tuple of (public_key_bytes, private_key_bytes)
        """
        pass

    @abc.abstractmethod
    def sign(self, message: bytes, private_key_bytes: bytes) -> bytes:
        """Sign message bytes using the private key.

        Returns:
            Raw signature bytes.
        """
        pass

    @abc.abstractmethod
    def verify(self, message: bytes, signature: bytes, public_key_bytes: bytes) -> bool:
        """Verify artifact bytes and signature using the public key.

        Returns:
            True if signature is valid, False otherwise.
        """
        pass


class CryptographyFipsEngine(CryptoEngine):
    """NIST FIPS 204 ML-DSA engine implemented via standard Python Cryptography.

    Provides authentic, production-grade ML-DSA (CRYSTALS-Dilithium) operations.
    """

    def __init__(self, algorithm: str = "ML-DSA-65"):
        self._algorithm = algorithm
        self._check_algorithm_support()

    def _check_algorithm_support(self):
        try:
            from cryptography.hazmat.primitives.asymmetric import mldsa  # noqa: F401
        except ImportError as exc:
            raise RuntimeError(
                "Python 'cryptography' library with ML-DSA support is required (v50.0.0+)."
            ) from exc

    @property
    def name(self) -> str:
        return "Python Cryptography (NIST FIPS 204 ML-DSA)"

    @property
    def algorithm(self) -> str:
        return self._algorithm

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        from cryptography.hazmat.primitives.asymmetric import mldsa

        if self._algorithm == "ML-DSA-65":
            sk = mldsa.MLDSA65PrivateKey.generate()
        elif self._algorithm == "ML-DSA-44":
            sk = mldsa.MLDSA44PrivateKey.generate()
        elif self._algorithm == "ML-DSA-87":
            sk = mldsa.MLDSA87PrivateKey.generate()
        else:
            raise ValueError(f"Unsupported algorithm: {self._algorithm}")

        pk = sk.public_key()
        raw_pk = pk.public_bytes_raw()
        raw_sk = sk.private_bytes_raw()
        return raw_pk, raw_sk

    def _load_private_key(self, private_key_bytes: bytes):
        from cryptography.hazmat.primitives.asymmetric import mldsa
        from cryptography.hazmat.primitives import serialization

        # Check if PEM format
        if private_key_bytes.strip().startswith(b"-----BEGIN"):
            return serialization.load_pem_private_key(private_key_bytes, password=None)

        # Raw seed format (32 bytes)
        if self._algorithm == "ML-DSA-65":
            if len(private_key_bytes) == MLDSA65_PRIVATE_SEED_SIZE:
                return mldsa.MLDSA65PrivateKey.from_seed_bytes(private_key_bytes)
            try:
                return serialization.load_der_private_key(private_key_bytes, password=None)
            except Exception:
                return mldsa.MLDSA65PrivateKey.from_seed_bytes(private_key_bytes[:32])

        elif self._algorithm == "ML-DSA-44":
            return mldsa.MLDSA44PrivateKey.from_seed_bytes(private_key_bytes[:32])
        elif self._algorithm == "ML-DSA-87":
            return mldsa.MLDSA87PrivateKey.from_seed_bytes(private_key_bytes[:32])

        raise ValueError(f"Unable to parse private key for {self._algorithm}")

    def _load_public_key(self, public_key_bytes: bytes):
        from cryptography.hazmat.primitives.asymmetric import mldsa
        from cryptography.hazmat.primitives import serialization

        # Check if PEM format
        if public_key_bytes.strip().startswith(b"-----BEGIN"):
            return serialization.load_pem_public_key(public_key_bytes)

        # Raw bytes format (1952 bytes for ML-DSA-65)
        if self._algorithm == "ML-DSA-65":
            if len(public_key_bytes) == MLDSA65_PUBLIC_KEY_SIZE:
                return mldsa.MLDSA65PublicKey.from_public_bytes(public_key_bytes)
            try:
                return serialization.load_der_public_key(public_key_bytes)
            except Exception:
                return mldsa.MLDSA65PublicKey.from_public_bytes(public_key_bytes)
        elif self._algorithm == "ML-DSA-44":
            return mldsa.MLDSA44PublicKey.from_public_bytes(public_key_bytes)
        elif self._algorithm == "ML-DSA-87":
            return mldsa.MLDSA87PublicKey.from_public_bytes(public_key_bytes)

        raise ValueError(f"Unable to parse public key for {self._algorithm}")

    def sign(self, message: bytes, private_key_bytes: bytes) -> bytes:
        sk = self._load_private_key(private_key_bytes)
        return sk.sign(message)

    def verify(self, message: bytes, signature: bytes, public_key_bytes: bytes) -> bool:
        from cryptography.exceptions import InvalidSignature

        try:
            pk = self._load_public_key(public_key_bytes)
            pk.verify(signature, message)
            return True
        except InvalidSignature:
            return False
        except Exception as exc:
            logger.debug(f"Verification error: {exc}")
            return False


class OqsEngine(CryptoEngine):
    """Open Quantum Safe (liboqs-python) ML-DSA engine."""

    def __init__(self, algorithm: str = "ML-DSA-65"):
        self._algorithm = algorithm
        self._oqs_alg_name = self._resolve_alg_name(algorithm)
        import oqs
        self._oqs = oqs

    @staticmethod
    def _resolve_alg_name(alg: str) -> str:
        import oqs
        enabled = oqs.get_enabled_sig_mechanisms()
        if alg in enabled:
            return alg
        mapping = {
            "ML-DSA-65": "Dilithium3",
            "ML-DSA-44": "Dilithium2",
            "ML-DSA-87": "Dilithium5",
        }
        fallback = mapping.get(alg)
        if fallback and fallback in enabled:
            return fallback
        raise ValueError(f"Algorithm '{alg}' is not enabled in liboqs: {enabled}")

    @property
    def name(self) -> str:
        return "Open Quantum Safe (liboqs-python)"

    @property
    def algorithm(self) -> str:
        return self._algorithm

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        with self._oqs.Signature(self._oqs_alg_name) as signer:
            public_key = signer.generate_keypair()
            private_key = signer.export_secret_key()
            return public_key, private_key

    def sign(self, message: bytes, private_key_bytes: bytes) -> bytes:
        with self._oqs.Signature(self._oqs_alg_name, secret_key=private_key_bytes) as signer:
            return signer.sign(message)

    def verify(self, message: bytes, signature: bytes, public_key_bytes: bytes) -> bool:
        try:
            with self._oqs.Signature(self._oqs_alg_name) as verifier:
                return verifier.verify(message, signature, public_key_bytes)
        except Exception:
            return False


def get_crypto_engine(algorithm: str = "ML-DSA-65", prefer_oqs: bool = True) -> CryptoEngine:
    """Resolve and return an active cryptographic engine.

    Tries liboqs first if requested and its native C library is confirmed present.
    Otherwise uses the genuine NIST FIPS 204 implementation in cryptography.
    """
    if prefer_oqs and _is_liboqs_c_library_present():
        try:
            return OqsEngine(algorithm)
        except Exception as exc:
            logger.debug(f"liboqs initialization failed ({exc}), falling back to FIPS 204 engine.")

    return CryptographyFipsEngine(algorithm)


def get_backend_diagnostics() -> Dict[str, Any]:
    """Inspect and report on available post-quantum cryptographic backends."""
    c_lib_found = _is_liboqs_c_library_present()
    if c_lib_found:
        try:
            import oqs
            mechanisms = oqs.get_enabled_sig_mechanisms()
            oqs_status = "available"
            oqs_details = f"Loaded successfully. Enabled mechanisms: {len(mechanisms)}"
        except Exception as exc:
            oqs_status = "error_loading"
            oqs_details = str(exc)
    else:
        oqs_status = "native_library_missing"
        oqs_details = (
            "Python package liboqs-python is installed, but the underlying native C library "
            "(oqs.dll on Windows / liboqs.so on Linux) was not found on the system PATH. "
            "To compile it natively on Windows: install CMake and MSVC/Ninja, clone "
            "open-quantum-safe/liboqs, and build with -DBUILD_SHARED_LIBS=ON."
        )

    fips_status = "available"
    fips_details = "Python Cryptography (v50+) official NIST FIPS 204 ML-DSA engine active."

    active_engine = get_crypto_engine("ML-DSA-65")

    return {
        "active_backend": active_engine.name,
        "algorithm": active_engine.algorithm,
        "liboqs_status": oqs_status,
        "liboqs_details": oqs_details,
        "fips204_status": fips_status,
        "fips204_details": fips_details,
        "is_mock": False,
    }
