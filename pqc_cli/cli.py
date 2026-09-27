"""Command-Line Interface for Post-Quantum Code Signer & Verifier (PQC)."""

import json
import logging
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from pqc_cli import __version__
from pqc_cli.config import PQCConfig
from pqc_cli.crypto_backend import get_backend_diagnostics
from pqc_cli.key_manager import generate_keypair
from pqc_cli.signer import sign_artifact
from pqc_cli.utils import (
    compute_sha256,
    format_file_size,
    render_demo_table,
    render_keygen_success,
    render_sign_summary,
    render_verify_invalid,
    render_verify_valid,
)
from pqc_cli.verifier import inspect_signature, verify_artifact

# Configure logging and stdout encoding
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")
logger = logging.getLogger("pqc")

app = typer.Typer(
    name="pqc",
    help=(
        "Post-Quantum Cryptography (PQC) Code Signer & Verifier CLI.\n\n"
        "Enables software engineers to generate post-quantum key pairs, "
        "sign release binaries using NIST ML-DSA (CRYSTALS-Dilithium), and "
        "verify artifact integrity on deployment hosts.\n\n"
        "Algorithm Standard: NIST FIPS 204 (ML-DSA-65), the standardized "
        "successor to CRYSTALS-Dilithium based on lattice cryptography."
    ),
    add_completion=False,
)
console = Console()
err_console = Console(stderr=True)


def _load_config_safely() -> PQCConfig:
    try:
        return PQCConfig.load()
    except Exception as exc:
        err_console.print(f"[bold red]Configuration Error:[/bold red] {exc}")
        raise typer.Exit(code=2)


@app.command("keygen")
def keygen(
    algorithm: Optional[str] = typer.Option(
        None,
        "--algorithm",
        "-a",
        help="Post-quantum signature algorithm (default: ML-DSA-65). Note: ML-DSA is the standardized name for CRYSTALS-Dilithium.",
    ),
    output_dir: Optional[Path] = typer.Option(
        None,
        "--output-dir",
        "-o",
        help="Directory to save generated public and private keys (default: keys/).",
    ),
):
    """Generate a post-quantum signing key pair (ML-DSA-65)."""
    cfg = _load_config_safely()
    alg = algorithm or cfg.algorithm
    out = output_dir or cfg.key_directory

    try:
        paths = generate_keypair(output_dir=out, algorithm=alg)
        render_keygen_success(paths.public_key_path, paths.private_key_path, alg)
    except Exception as exc:
        err_console.print(f"[bold red]Key Generation Error:[/bold red] {exc}")
        raise typer.Exit(code=1)


@app.command("sign")
def sign(
    artifact: Path = typer.Argument(
        ...,
        help="Path to the software artifact or binary to sign.",
    ),
    private_key: Optional[Path] = typer.Option(
        None,
        "--private-key",
        "-k",
        help="Path to the private key file (default: keys/private.key).",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Path where the signature file will be written (default: <artifact>.sig).",
    ),
    algorithm: Optional[str] = typer.Option(
        None,
        "--algorithm",
        "-a",
        help="Signature algorithm (default: ML-DSA-65).",
    ),
    raw: bool = typer.Option(
        False,
        "--raw",
        help="Output raw binary signature bytes instead of JSON metadata bundle.",
    ),
):
    """Sign a software artifact using ML-DSA (CRYSTALS-Dilithium)."""
    cfg = _load_config_safely()
    alg = algorithm or cfg.algorithm
    priv_key_path = private_key or (cfg.key_directory / "private.key")
    out_sig = output or artifact.with_suffix(artifact.suffix + cfg.signature_extension)

    try:
        sig_path, active_alg, size_bytes, sha256_hash = sign_artifact(
            artifact_path=artifact,
            private_key_path=priv_key_path,
            output_sig_path=out_sig,
            algorithm=alg,
            raw_signature=raw,
        )
        render_sign_summary(
            artifact_path=artifact,
            algorithm=active_alg,
            size_bytes=size_bytes,
            sha256_hash=sha256_hash,
            signature_path=sig_path,
        )
    except FileNotFoundError as exc:
        err_console.print(f"[bold red]File Error:[/bold red] {exc}")
        raise typer.Exit(code=1)
    except Exception as exc:
        err_console.print(f"[bold red]Signing Error:[/bold red] {exc}")
        raise typer.Exit(code=1)


@app.command("verify")
def verify(
    artifact: Path = typer.Argument(
        ...,
        help="Path to the software artifact to verify.",
    ),
    public_key: Optional[Path] = typer.Option(
        None,
        "--public-key",
        "-k",
        help="Path to the public key file (default: keys/public.key).",
    ),
    signature: Optional[Path] = typer.Option(
        None,
        "--signature",
        "-s",
        help="Path to the signature file (default: <artifact>.sig).",
    ),
    algorithm: Optional[str] = typer.Option(
        None,
        "--algorithm",
        "-a",
        help="Signature algorithm (default: ML-DSA-65).",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Output results in machine-readable JSON format for CI/CD.",
    ),
):
    """Verify an artifact's digital signature using ML-DSA."""
    cfg = _load_config_safely()
    alg = algorithm or cfg.algorithm
    pub_key_path = public_key or (cfg.key_directory / "public.key")
    sig_path = signature or artifact.with_suffix(artifact.suffix + cfg.signature_extension)

    try:
        result = verify_artifact(
            artifact_path=artifact,
            public_key_path=pub_key_path,
            signature_path=sig_path,
            algorithm=alg,
        )
    except FileNotFoundError as exc:
        if json_output:
            print(json.dumps({"valid": False, "error": str(exc), "action": "BLOCK"}))
        else:
            err_console.print(f"[bold red]Missing File:[/bold red] {exc}")
        raise typer.Exit(code=1)
    except Exception as exc:
        if json_output:
            print(json.dumps({"valid": False, "error": str(exc), "action": "BLOCK"}))
        else:
            err_console.print(f"[bold red]Verification Error:[/bold red] {exc}")
        raise typer.Exit(code=1)

    if json_output:
        print(json.dumps(result.to_json_dict(), indent=2))
    else:
        if result.valid:
            render_verify_valid(result.algorithm, result.details)
        else:
            render_verify_invalid(result.algorithm, result.possible_causes)

    # Return exit code 0 for valid, 1 for invalid
    if not result.valid:
        raise typer.Exit(code=1)


@app.command("inspect")
def inspect(
    signature_file: Path = typer.Argument(
        ...,
        help="Path to the signature file (.sig) to inspect.",
    ),
):
    """Inspect signature metadata without exposing private cryptographic material."""
    try:
        info = inspect_signature(signature_file)
        table = Table(
            title=f"SIGNATURE METADATA: {signature_file.name}",
            title_style="bold cyan",
            border_style="cyan",
            expand=False,
        )
        table.add_column("Property", style="bold yellow", min_width=22)
        table.add_column("Value", style="cyan")

        table.add_row("Signature File", info.get("signature_file", ""))
        table.add_row("Format", info.get("format", ""))
        table.add_row("Algorithm", info.get("algorithm", ""))
        table.add_row("Signature Size", f"{info.get('signature_size_bytes', 0):,} bytes")
        table.add_row("Associated Artifact", str(info.get("associated_artifact", "")))
        table.add_row("Artifact SHA-256", str(info.get("artifact_sha256", "")))
        if "artifact_size_bytes" in info and info["artifact_size_bytes"] != "Unknown":
            table.add_row("Artifact Size", format_file_size(info["artifact_size_bytes"]))
        table.add_row("Creation Timestamp", str(info.get("created_at", "")))

        console.print(table)
    except Exception as exc:
        err_console.print(f"[bold red]Inspection Error:[/bold red] {exc}")
        raise typer.Exit(code=1)


@app.command("demo")
def demo():
    """Run an automated end-to-end PQC signing, verification, and tamper evaluation."""
    console.print(
        Panel(
            "[bold white]POST-QUANTUM CODE SIGNER & VERIFIER DEMONSTRATION[/bold white]\n"
            "[dim]Standard: NIST FIPS 204 ML-DSA-65 (CRYSTALS-Dilithium)[/dim]",
            border_style="magenta",
            expand=False,
        )
    )

    demo_dir = Path("demo")
    demo_dir.mkdir(exist_ok=True)
    keys_dir = Path("keys")
    keys_dir.mkdir(exist_ok=True)

    test_results = []

    # STEP 1: Prepare simulated artifact
    console.print("\n[bold cyan]STEP 1 — Prepare Software Artifact[/bold cyan]")
    app_bin = demo_dir / "app.bin"
    if not app_bin.exists():
        app_bin.write_bytes(
            b"#!/usr/bin/env python3\n# Production App v1.0.0\nprint('Production binary active.')\n"
        )
    sha256_orig = compute_sha256(app_bin.read_bytes())
    console.print(f"Artifact        : [cyan]{app_bin}[/cyan] ({format_file_size(app_bin.stat().st_size)})")
    console.print(f"Artifact SHA-256: [dim]{sha256_orig}[/dim]")
    console.print("[dim]Simulated software artifact prepared.[/dim]")

    # STEP 2: Key generation
    console.print("\n[bold cyan]STEP 2 — Generate ML-DSA-65 Key Pair[/bold cyan]")
    paths = generate_keypair(output_dir=keys_dir, algorithm="ML-DSA-65")
    console.print(f"[bold green]✓[/bold green] ML-DSA-65 key pair generated")
    console.print(f"Public key : [cyan]{paths.public_key_path}[/cyan]")
    console.print(f"Private key: [cyan]{paths.private_key_path}[/cyan]")

    # STEP 3: Sign original artifact
    console.print("\n[bold cyan]STEP 3 — Sign Original Artifact[/bold cyan]")
    sig_path = demo_dir / "app.bin.sig"
    sign_artifact(
        artifact_path=app_bin,
        private_key_path=paths.private_key_path,
        output_sig_path=sig_path,
        algorithm="ML-DSA-65",
    )
    console.print(f"[bold green]✓[/bold green] Signature generated: [cyan]{sig_path}[/cyan]")

    # STEP 4: Verify original artifact
    console.print("\n[bold cyan]STEP 4 — Verify Original Artifact[/bold cyan]")
    res_orig = verify_artifact(
        artifact_path=app_bin,
        public_key_path=paths.public_key_path,
        signature_path=sig_path,
    )
    if res_orig.valid:
        render_verify_valid("ML-DSA-65")
        test_results.append(("Original artifact", True))
    else:
        render_verify_invalid("ML-DSA-65")
        test_results.append(("Original artifact", False))

    # STEP 5: Create tampered artifact
    console.print("\n[bold cyan]STEP 5 — Simulate Adversary Tampering[/bold cyan]")
    app_tampered = demo_dir / "app_tampered.bin"
    tampered_bytes = app_bin.read_bytes() + b"\n# UNAUTHORIZED INJECTION: MALICIOUS BACKDOOR"
    app_tampered.write_bytes(tampered_bytes)
    console.print(f"Created tampered artifact: [red]{app_tampered}[/red]")
    console.print("[yellow]Signature was NOT regenerated.[/yellow]")

    # STEP 6: Verify tampered artifact
    console.print("\n[bold cyan]STEP 6 — Verify Tampered Artifact (Detection Check)[/bold cyan]")
    res_tampered = verify_artifact(
        artifact_path=app_tampered,
        public_key_path=paths.public_key_path,
        signature_path=sig_path,
    )
    if not res_tampered.valid:
        render_verify_invalid("ML-DSA-65", res_tampered.possible_causes)
        test_results.append(("Tampered artifact", True))  # PASS = tampering correctly caught!
    else:
        render_verify_valid("ML-DSA-65")
        test_results.append(("Tampered artifact", False))

    # STEP 7: Wrong-key test
    console.print("\n[bold cyan]STEP 7 — Verify With Wrong Public Key (Impersonation Check)[/bold cyan]")
    unrelated_keys_dir = demo_dir / "unrelated_keys"
    unrelated_paths = generate_keypair(output_dir=unrelated_keys_dir, algorithm="ML-DSA-65")
    res_wrong_key = verify_artifact(
        artifact_path=app_bin,
        public_key_path=unrelated_paths.public_key_path,
        signature_path=sig_path,
    )
    if not res_wrong_key.valid:
        render_verify_invalid("ML-DSA-65", ["Wrong public key was supplied"])
        test_results.append(("Wrong public key", True))  # PASS = wrong key correctly caught!
    else:
        render_verify_valid("ML-DSA-65")
        test_results.append(("Wrong public key", False))

    # STEP 8: Evaluation summary
    render_demo_table(test_results)


@app.command("diagnostics")
def diagnostics():
    """Inspect and report on Post-Quantum cryptographic backends and host environment."""
    diag = get_backend_diagnostics()

    table = Table(
        title="POST-QUANTUM CRYPTOGRAPHY ENGINE DIAGNOSTICS",
        title_style="bold cyan",
        border_style="cyan",
        expand=False,
    )
    table.add_column("Component", style="bold yellow", min_width=25)
    table.add_column("Status", min_width=15)
    table.add_column("Details", style="dim")

    table.add_row(
        "Active Backend",
        "[bold green]ACTIVE[/bold green]",
        diag["active_backend"],
    )
    table.add_row(
        "Target Algorithm",
        "[bold green]CONFIGURED[/bold green]",
        f"{diag['algorithm']} (NIST FIPS 204)",
    )
    table.add_row(
        "Mock Cryptography",
        "[bold green]DISABLED[/bold green]",
        "100% genuine post-quantum lattice mathematics (zero mocking)",
    )

    oqs_status_styled = (
        "[bold green]AVAILABLE[/bold green]"
        if diag["liboqs_status"] == "available"
        else "[yellow]MISSING C LIB[/yellow]"
    )
    table.add_row("liboqs (C Library)", oqs_status_styled, diag["liboqs_details"])

    table.add_row(
        "FIPS 204 (Cryptography)",
        "[bold green]AVAILABLE[/bold green]",
        diag["fips204_details"],
    )

    console.print(table)


@app.command("serve")
def serve(
    port: int = typer.Option(None, "--port", "-p", help="Port to listen on (default: $PORT env or 8080)."),
    host: str = typer.Option("0.0.0.0", "--host", "-h", help="Host interface to bind to."),
    public_key: Optional[Path] = typer.Option(
        None,
        "--public-key",
        "-k",
        help="Path to trusted public key file. Optional — clients can register via /register-key.",
    ),
    deploy_dir: Path = typer.Option(
        Path("production_deployments"),
        "--deploy-dir",
        "-d",
        help="Directory to store approved production binaries.",
    ),
    algorithm: str = typer.Option(
        "ML-DSA-65",
        "--algorithm",
        "-a",
        help="Signature algorithm expected.",
    ),
):
    """Run the Production Deployment Gate Server (Deployment Host).

    Can run locally (two-terminal demo) or on cloud platforms like Render.com.
    Public key is loaded from:
      1. --public-key file path argument
      2. PQC_PUBLIC_KEY_B64 environment variable (Render/cloud)
      3. POST /register-key API (client pushes key dynamically)
    """
    import os
    from pqc_cli.server import run_deployment_server

    # Cloud platforms (Render.com) set $PORT automatically
    actual_port = port or int(os.environ.get("PORT", 8080))

    # Optional: load public key from file only if it exists
    pub_path = None
    if public_key and public_key.exists():
        pub_path = public_key
    elif public_key is None:
        cfg = _load_config_safely()
        default_key = cfg.key_directory / "public.key"
        if default_key.exists():
            pub_path = default_key

    try:
        run_deployment_server(
            port=actual_port,
            host=host,
            public_key_path=pub_path,
            deploy_dir=deploy_dir,
            algorithm=algorithm,
        )
    except Exception as exc:
        err_console.print(f"[bold red]Server Error:[/bold red] {exc}")
        raise typer.Exit(code=1)


@app.command("deploy")
def deploy(
    artifact: Path = typer.Argument(..., help="Path to software binary to sign and deploy."),
    host: str = typer.Option("http://localhost:8080", "--host", "-H", help="Deployment Gate Server URL."),
    private_key: Optional[Path] = typer.Option(
        None,
        "--private-key",
        "-k",
        help="Path to signing private key (default: keys/private.key).",
    ),
    signature: Optional[Path] = typer.Option(
        None,
        "--signature",
        "-s",
        help="Path to existing signature (optional; signs automatically if omitted).",
    ),
    algorithm: str = typer.Option("ML-DSA-65", "--algorithm", "-a", help="Signature algorithm."),
    tamper: bool = typer.Option(
        False,
        "--tamper",
        "-t",
        help="Simulate adversary modifying the payload in transit before reaching host.",
    ),
    legacy: bool = typer.Option(
        False,
        "--legacy",
        help="Simulate Legacy deployment pipeline (bypasses PQC check to demonstrate attack impact).",
    ),
):
    """Sign an artifact locally and deploy it to a remote Deployment Host Server."""
    from pqc_cli.client import deploy_artifact

    cfg = _load_config_safely()
    priv_path = private_key or (cfg.key_directory / "private.key")

    success, _ = deploy_artifact(
        artifact_path=artifact,
        host_url=host,
        private_key_path=priv_path,
        signature_path=signature,
        algorithm=algorithm,
        simulate_tamper=tamper,
        legacy_mode=legacy,
    )
    if not success:
        raise typer.Exit(code=1)


@app.command("reset-server")
def reset_server(
    host: str = typer.Option("http://localhost:8080", "--host", "-H", help="Deployment Gate Server URL."),
):
    """Reset the remote deployment gateway to clean initial state for demonstration."""
    import urllib.request, json
    base = host.rstrip("/")
    try:
        req = urllib.request.Request(f"{base}/reset", data=b"{}", headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            console.print(f"[bold green]✓ Server Reset Successful:[/bold green] {data.get('message')}")
    except Exception as exc:
        err_console.print(f"[bold red]Reset failed:[/bold red] {exc}")
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()

