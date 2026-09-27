"""Configuration module for PQC CLI."""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


SUPPORTED_ALGORITHMS = ["ML-DSA-65", "ML-DSA-44", "ML-DSA-87"]
DEFAULT_CONFIG_PATH = Path("config.json")


@dataclass
class PQCConfig:
    algorithm: str = "ML-DSA-65"
    key_directory: Path = Path("keys")
    signature_extension: str = ".sig"
    default_output_directory: Path = Path("demo")

    @classmethod
    def load(cls, path: Optional[Path] = None) -> "PQCConfig":
        config_file = path or DEFAULT_CONFIG_PATH
        if not config_file.exists():
            return cls()

        try:
            with open(config_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            algorithm = data.get("algorithm", "ML-DSA-65")
            if algorithm not in SUPPORTED_ALGORITHMS:
                raise ValueError(
                    f"Unsupported algorithm '{algorithm}' in {config_file}. "
                    f"Supported algorithms: {', '.join(SUPPORTED_ALGORITHMS)}"
                )

            key_directory = Path(data.get("key_directory", "keys"))
            signature_extension = data.get("signature_extension", ".sig")
            default_output_directory = Path(data.get("default_output_directory", "demo"))

            return cls(
                algorithm=algorithm,
                key_directory=key_directory,
                signature_extension=signature_extension,
                default_output_directory=default_output_directory,
            )
        except json.JSONDecodeError as exc:
            raise ValueError(f"Malformed configuration file '{config_file}': {exc}") from exc
        except Exception as exc:
            raise ValueError(f"Error loading configuration file '{config_file}': {exc}") from exc
