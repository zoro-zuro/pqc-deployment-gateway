"""Tests for HTTP Deployment Gate Server and Client."""

import threading
import time
from http.server import HTTPServer
from pathlib import Path
import pytest

from pqc_cli.client import deploy_artifact
from pqc_cli.key_manager import generate_keypair
from pqc_cli.server import DeploymentGateHandler


@pytest.fixture
def running_server(tmp_path: Path):
    """Fixture to start a test deployment gate server in a background thread."""
    keys_dir = tmp_path / "keys"
    paths = generate_keypair(output_dir=keys_dir, algorithm="ML-DSA-65")
    deploy_dir = tmp_path / "staged_deployments"

    DeploymentGateHandler.public_key_path = paths.public_key_path
    DeploymentGateHandler.deploy_dir = deploy_dir
    DeploymentGateHandler.algorithm = "ML-DSA-65"

    port = 8765
    server = HTTPServer(("127.0.0.1", port), DeploymentGateHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    time.sleep(0.1)

    yield {
        "url": f"http://127.0.0.1:{port}",
        "paths": paths,
        "deploy_dir": deploy_dir,
    }

    server.shutdown()
    server.server_close()


def test_server_valid_deployment(tmp_path: Path, running_server):
    """Test deploying a valid signed artifact over network to server."""
    artifact = tmp_path / "production_app.bin"
    artifact.write_bytes(b"Clean release build 2026")

    success, resp = deploy_artifact(
        artifact_path=artifact,
        host_url=running_server["url"],
        private_key_path=running_server["paths"].private_key_path,
        algorithm="ML-DSA-65",
    )

    assert success is True
    assert resp.get("decision") == "ALLOW"
    assert resp.get("status") == "DEPLOYED"

    # Verify server staged the file
    staged = running_server["deploy_dir"] / "production_app.bin"
    assert staged.exists()
    assert staged.read_bytes() == artifact.read_bytes()


def test_server_tampered_deployment_blocked(tmp_path: Path, running_server):
    """Test that in-transit tampering is caught by the server and blocked with HTTP 403."""
    artifact = tmp_path / "tampered_app.bin"
    artifact.write_bytes(b"Target release build")

    success, resp = deploy_artifact(
        artifact_path=artifact,
        host_url=running_server["url"],
        private_key_path=running_server["paths"].private_key_path,
        algorithm="ML-DSA-65",
        simulate_tamper=True,
    )

    assert success is False
    assert resp.get("decision") == "BLOCK"
    assert resp.get("status") == "REJECTED"
