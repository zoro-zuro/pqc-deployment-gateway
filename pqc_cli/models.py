"""Data models for PQC Code Signer & Verifier."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class KeyPairPaths:
    """Paths to generated public and private key files."""
    public_key_path: Path
    private_key_path: Path
    algorithm: str


@dataclass
class SignatureBundle:
    """Structure storing signature bytes along with metadata for inspection."""
    version: str
    algorithm: str
    artifact_name: str
    artifact_sha256: str
    artifact_size: int
    created_at: str
    signature_bytes: bytes

    def to_dict(self) -> Dict[str, Any]:
        import base64
        return {
            "format": "pqc-signature-v1",
            "version": self.version,
            "algorithm": self.algorithm,
            "artifact": self.artifact_name,
            "artifact_sha256": self.artifact_sha256,
            "artifact_size": self.artifact_size,
            "created_at": self.created_at,
            "signature_size": len(self.signature_bytes),
            "signature": base64.b64encode(self.signature_bytes).decode("ascii"),
        }


@dataclass
class VerificationResult:
    """Outcome of signature and artifact verification."""
    valid: bool
    algorithm: str
    artifact: str
    signature: str
    action: str  # "DEPLOY" or "BLOCK"
    integrity_status: str  # "VERIFIED" or "FAILED"
    signer_status: str  # "PASSED" or "FAILED"
    details: List[str] = field(default_factory=list)
    possible_causes: List[str] = field(default_factory=list)

    def to_json_dict(self) -> Dict[str, Any]:
        """JSON output dictionary matching specification for CI/CD automation."""
        return {
            "valid": self.valid,
            "algorithm": self.algorithm,
            "artifact": self.artifact,
            "signature": self.signature,
            "action": self.action,
        }
