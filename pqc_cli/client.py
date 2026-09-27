"""Client module: Sign artifacts locally and deploy to remote PQC Gateway Server."""

import base64
import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional, Tuple

from rich.console import Console
from rich.panel import Panel

from pqc_cli.crypto_backend import get_crypto_engine
from pqc_cli.key_manager import load_private_key, load_public_key
from pqc_cli.utils import TICK, CROSS, WARN, compute_sha256, format_file_size

console = Console(highlight=False)


def _http_post(url: str, payload: dict, timeout: int = 30) -> Tuple[int, dict]:
    """POST JSON payload to URL. Returns (status_code, response_dict)."""
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "PQC-Deployment-Client/1.0",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            body = json.loads(exc.read().decode("utf-8"))
        except Exception:
            body = {"error": str(exc)}
        return exc.code, body
    except urllib.error.URLError as exc:
        raise ConnectionError(f"Cannot reach server at {url}: {exc.reason}")


def _http_get(url: str, timeout: int = 10) -> Tuple[int, dict]:
    """GET request. Returns (status_code, response_dict)."""
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "PQC-Deployment-Client/1.0"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, {}
    except urllib.error.URLError as exc:
        raise ConnectionError(f"Cannot reach server: {exc.reason}")


def check_server_health(host_url: str) -> dict:
    """Check if the deployment server is reachable and healthy."""
    base = host_url.rstrip("/")
    _, data = _http_get(f"{base}/health")
    return data


def register_public_key(host_url: str, public_key_path: Path, algorithm: str = "ML-DSA-65") -> bool:
    """Register local public key with the remote deployment gate server."""
    pub_bytes = load_public_key(public_key_path)
    base = host_url.rstrip("/")

    console.print(f"  Registering public key with server...")

    code, resp = _http_post(f"{base}/register-key", {
        "public_key_b64": base64.b64encode(pub_bytes).decode("ascii"),
        "algorithm": algorithm,
    })

    if code == 200:
        console.print(f"  [bold green]{TICK} Public key registered ({len(pub_bytes):,} bytes)[/bold green]")
        return True
    else:
        console.print(f"  [red]{CROSS} Key registration failed: {resp.get('error')}[/red]")
        return False


def deploy_artifact(
    artifact_path: Path,
    host_url: str,
    private_key_path: Path = Path("keys/private.key"),
    public_key_path: Optional[Path] = None,
    signature_path: Optional[Path] = None,
    algorithm: str = "ML-DSA-65",
    simulate_tamper: bool = False,
    auto_register_key: bool = True,
    legacy_mode: bool = False,
) -> Tuple[bool, dict]:
    """Sign artifact locally and deploy to a remote PQC Deployment Gate Server.

    Flow:
    1. Check server reachability
    2. Auto-register public key if server doesn't have one yet
    3. Sign artifact locally with private key
    4. (Optional) Simulate in-transit tampering
    5. POST to /deploy — server verifies with ML-DSA-65
    6. Return (success, response)
    """
    artifact_path = Path(artifact_path)
    if not artifact_path.exists():
        raise FileNotFoundError(f"Artifact not found: {artifact_path}")

    base_url = host_url.rstrip("/")
    console.print(f"\n[bold cyan]PQC DEPLOYMENT CLIENT[/bold cyan]")
    console.print(f"Target Host: [cyan]{base_url}[/cyan]")
    console.print(f"Artifact   : [cyan]{artifact_path}[/cyan] ({format_file_size(artifact_path.stat().st_size)})")
    console.print(f"Algorithm  : [bold]{algorithm}[/bold] (NIST FIPS 204)\n")

    # Step 1: Health check
    console.print(f"[dim]Step 1/4 — Checking server health...[/dim]")
    try:
        health = check_server_health(base_url)
        console.print(f"  Server: [bold green]ONLINE[/bold green] | Algorithm: {health.get('algorithm', algorithm)}")
        key_registered = health.get("public_key_registered", False)
    except ConnectionError as exc:
        console.print(f"[bold red]{CROSS} Connection failed:[/bold red] {exc}")
        return False, {"error": str(exc), "decision": "BLOCK"}

    # Step 2: Register public key if needed
    console.print(f"[dim]Step 2/4 — Public key registration...[/dim]")
    if not key_registered and auto_register_key:
        pub_path = public_key_path or Path(str(private_key_path).replace("private.key", "public.key"))
        if pub_path.exists():
            ok = register_public_key(base_url, pub_path, algorithm)
            if not ok:
                console.print(f"[bold red]{CROSS} Cannot proceed without registered public key.[/bold red]")
                return False, {"error": "Key registration failed", "decision": "BLOCK"}
        else:
            console.print(f"  [yellow]{WARN} Public key not found at {pub_path}. Using server's existing key.[/yellow]")
    else:
        console.print(f"  [bold green]{TICK} Server already has trusted public key[/bold green]")

    # Step 3: Sign artifact
    console.print(f"[dim]Step 3/4 — Signing artifact locally with private key...[/dim]")
    with open(artifact_path, "rb") as f:
        artifact_bytes = f.read()
    sha256 = compute_sha256(artifact_bytes)

    if signature_path and Path(signature_path).exists():
        # Use existing signature bundle
        from pqc_cli.verifier import parse_signature_file
        signature_bytes, _ = parse_signature_file(Path(signature_path))
        console.print(f"  [dim]Using existing signature from {signature_path}[/dim]")
    else:
        # Sign fresh
        priv_path = Path(private_key_path)
        if not priv_path.exists():
            raise FileNotFoundError(f"Private key not found: {priv_path}")
        priv_bytes = load_private_key(priv_path)
        engine = get_crypto_engine(algorithm)
        signature_bytes = engine.sign(artifact_bytes, priv_bytes)

    console.print(f"  [bold green]{TICK} ML-DSA-65 signature ready ({len(signature_bytes):,} bytes)[/bold green]")
    console.print(f"  SHA-256: [dim]{sha256}[/dim]")

    # Step 4: Simulate in-transit tampering (optional)
    if simulate_tamper:
        console.print(f"\n[bold red]{WARN} ADVERSARY SIMULATION: Injecting payload before network dispatch![/bold red]")
        console.print(f"[dim]Appending unauthorized backdoor bytes to artifact bytes in transit...[/dim]")
        artifact_bytes = artifact_bytes + b"\n# UNAUTHORIZED BACKDOOR INJECTED IN TRANSIT"
        sha256_tampered = compute_sha256(artifact_bytes)
        console.print(f"  Original SHA-256 : [dim]{sha256}[/dim]")
        console.print(f"  Tampered SHA-256 : [bold red]{sha256_tampered}[/bold red]")

    # Step 4: Send to server
    endpoint = "/legacy-deploy" if legacy_mode else "/deploy"
    console.print(f"\n[dim]Step 4/4 — Sending to Deployment Gate...[/dim]")
    console.print(f"  POST {base_url}{endpoint}")

    code, resp = _http_post(f"{base_url}{endpoint}", {
        "artifact_name": artifact_path.name,
        "artifact_bytes": base64.b64encode(artifact_bytes).decode("ascii"),
        "signature_bytes": base64.b64encode(signature_bytes).decode("ascii"),
        "algorithm": algorithm,
    }, timeout=60)

    # Display result
    if code == 200:
        console.print(
            Panel(
                f"Server Decision : [bold green]{resp.get('decision')}[/bold green]\n"
                f"Status         : [bold green]{resp.get('status')}[/bold green]\n"
                f"Artifact       : {resp.get('artifact')}\n"
                f"Server SHA-256 : [dim]{resp.get('sha256')}[/dim]\n"
                f"Message        : {resp.get('message')}",
                title=f"[bold green]{TICK} REMOTE DEPLOYMENT APPROVED[/bold green]",
                border_style="green",
                expand=False,
            )
        )
        return True, resp
    else:
        console.print(
            Panel(
                f"HTTP Code      : [bold red]{code}[/bold red]\n"
                f"Server Decision: [bold red]{resp.get('decision', 'BLOCK')}[/bold red]\n"
                f"Artifact       : {resp.get('artifact', artifact_path.name)}\n"
                f"Reason         : [yellow]{resp.get('error', 'Signature verification failed')}[/yellow]",
                title=f"[bold red]{CROSS} REMOTE HOST REJECTED DEPLOYMENT[/bold red]",
                border_style="red",
                expand=False,
            )
        )
        return False, resp
