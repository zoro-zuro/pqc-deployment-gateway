"""Tests for PQC CLI commands, exit codes, and JSON outputs."""

import json
from pathlib import Path
from typer.testing import CliRunner
from pqc_cli.cli import app

runner = CliRunner()


def test_cli_help():
    """Test pqc --help returns exit code 0."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "Post-Quantum" in result.output
    assert "ML-DSA-65" in result.output


def test_cli_diagnostics():
    """Test pqc diagnostics returns exit code 0."""
    result = runner.invoke(app, ["diagnostics"])
    assert result.exit_code == 0
    assert "DIAGNOSTICS" in result.output


def test_cli_keygen_sign_verify_workflow(tmp_path: Path):
    """Test end-to-end CLI workflow: keygen -> sign -> verify (valid & tampered)."""
    keys_dir = tmp_path / "keys"

    # 1. Keygen
    res_keygen = runner.invoke(app, ["keygen", "--output-dir", str(keys_dir)])
    assert res_keygen.exit_code == 0
    pub_key = keys_dir / "public.key"
    priv_key = keys_dir / "private.key"
    assert pub_key.exists()
    assert priv_key.exists()

    # 2. Prepare artifact
    artifact = tmp_path / "app.bin"
    artifact.write_bytes(b"Simulated software binary v1.0")

    # 3. Sign artifact
    sig_file = tmp_path / "app.bin.sig"
    res_sign = runner.invoke(
        app,
        [
            "sign",
            str(artifact),
            "--private-key",
            str(priv_key),
            "--output",
            str(sig_file),
        ],
    )
    assert res_sign.exit_code == 0
    assert sig_file.exists()

    # 4. Verify valid artifact (Exit code 0)
    res_verify = runner.invoke(
        app,
        [
            "verify",
            str(artifact),
            "--public-key",
            str(pub_key),
            "--signature",
            str(sig_file),
        ],
    )
    assert res_verify.exit_code == 0
    assert "DEPLOYMENT DECISION: ALLOW" in res_verify.output

    # 5. Verify valid artifact with --json
    res_verify_json = runner.invoke(
        app,
        [
            "verify",
            str(artifact),
            "--public-key",
            str(pub_key),
            "--signature",
            str(sig_file),
            "--json",
        ],
    )
    assert res_verify_json.exit_code == 0
    data = json.loads(res_verify_json.output)
    assert data["valid"] is True
    assert data["action"] == "DEPLOY"

    # 6. Inspect signature
    res_inspect = runner.invoke(app, ["inspect", str(sig_file)])
    assert res_inspect.exit_code == 0
    assert "ML-DSA-65" in res_inspect.output

    # 7. Modify artifact (adversary tamper)
    tampered_artifact = tmp_path / "app_tampered.bin"
    tampered_artifact.write_bytes(artifact.read_bytes() + b"evil_code")

    # 8. Verify tampered artifact (Exit code 1)
    res_tampered = runner.invoke(
        app,
        [
            "verify",
            str(tampered_artifact),
            "--public-key",
            str(pub_key),
            "--signature",
            str(sig_file),
        ],
    )
    assert res_tampered.exit_code == 1
    assert "DEPLOYMENT DECISION: BLOCK" in res_tampered.output

    # 9. Verify tampered artifact with --json (Exit code 1)
    res_tampered_json = runner.invoke(
        app,
        [
            "verify",
            str(tampered_artifact),
            "--public-key",
            str(pub_key),
            "--signature",
            str(sig_file),
            "--json",
        ],
    )
    assert res_tampered_json.exit_code == 1
    tampered_data = json.loads(res_tampered_json.output)
    assert tampered_data["valid"] is False
    assert tampered_data["action"] == "BLOCK"


def test_cli_verify_missing_file_exit_code(tmp_path: Path):
    """Test verify with non-existent artifact exits with non-zero code."""
    res = runner.invoke(app, ["verify", str(tmp_path / "nonexistent.bin")])
    assert res.exit_code != 0


def test_cli_demo():
    """Test pqc demo runs all steps and exits with code 0."""
    result = runner.invoke(app, ["demo"])
    assert result.exit_code == 0
    assert "DEMO EVALUATION" in result.output
    assert "100%" in result.output
    assert "3/3" in result.output
