"""Production Deployment Gate Server with Live FinTech Checkout UI & Audit Logs.

Supports:
- GET  /              - Live FinTech Checkout web application
- GET  /health        - Gateway status
- GET  /audit         - Real-time security audit log of deployments
- POST /register-key  - Dynamic ML-DSA-65 public key registration
- POST /deploy        - PQC cryptographic deployment gate (ALLOW / BLOCK)
- POST /legacy-deploy - Simulates unverified deployment (Scenario 1: Attack succeeds)
- POST /reset         - Instant clean state rollback for live presentations
"""

import base64
import html
import json
import logging
import os
import tempfile
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from rich.console import Console
from rich.panel import Panel

from pqc_cli.crypto_backend import get_crypto_engine
from pqc_cli.utils import TICK, CROSS, WARN, compute_sha256, format_file_size

logger = logging.getLogger("pqc.server")
console = Console(highlight=False)

_REGISTERED_PUBLIC_KEY: bytes = None
_REGISTERED_KEY_INFO: dict = {}

# Current live application state on server
# Current live cluster deployment state
_CURRENT_ARTIFACT: dict = {
    "name": "core-payment-service.bin",
    "version": "v1.0.0-GA",
    "status": "HEALTHY",
    "signature_state": "VERIFIED (NIST FIPS 204 ML-DSA-65)",
    "sha256": "8a3f91d20b7c44e91a0c8831ef5021a97d95f71c3b691faab07f557e16dfc7ab",
    "deployed_at": "Baseline Cluster Release",
    "compromised": False,
    "compromise_details": None,
}

_AUDIT_LOGS = []

def _record_audit(action: str, artifact: str, sha256: str, decision: str, reason: str):
    _AUDIT_LOGS.insert(0, {
        "timestamp": time.strftime("%H:%M:%S UTC"),
        "action": action,
        "artifact": artifact,
        "sha256": sha256[:16] + "..." if sha256 else "N/A",
        "decision": decision,
        "reason": reason
    })
    if len(_AUDIT_LOGS) > 15:
        _AUDIT_LOGS.pop()


def render_checkout_html() -> str:
    art = _CURRENT_ARTIFACT
    is_compromised = art["compromised"]
    is_pqc = "ML-DSA-65" in art["signature_state"] and not is_compromised

    status_badge_color = "#ef4444" if is_compromised else ("#10b981" if is_pqc else "#f59e0b")
    status_text = "COMPROMISED ARTIFACT IN PRODUCTION" if is_compromised else ("SECURED BY ML-DSA-65" if is_pqc else "UNVERIFIED RELEASE")

    audit_rows = ""
    for log in _AUDIT_LOGS:
        badge_cls = "badge-allow" if log["decision"] == "ALLOW" else ("badge-block" if log["decision"] == "BLOCK" else "badge-warn")
        audit_rows += f"""
        <tr>
            <td style="color:#94a3b8">{log['timestamp']}</td>
            <td style="font-weight:600">{html.escape(log['artifact'])}</td>
            <td><code style="color:#38bdf8">{html.escape(log['sha256'])}</code></td>
            <td><span class="{badge_cls}">{html.escape(log['decision'])}</span></td>
            <td style="color:#cbd5e1;font-size:0.85rem">{html.escape(log['reason'])}</td>
        </tr>
        """
    if not audit_rows:
        audit_rows = "<tr><td colspan='5' style='text-align:center;color:#64748b;padding:1.5rem'>No deployment events recorded yet. Ready for pipeline input.</td></tr>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enterprise Deployment Gate | Post-Quantum Cryptography</title>
    <style>
        :root {{
            --bg: #0b0f19;
            --surface: #111827;
            --border: #1f293d;
            --text: #f8fafc;
        }}
        * {{ margin:0; padding:0; box-sizing:border-box; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }}
        body {{ background: var(--bg); color: var(--text); padding: 2rem; min-height: 100vh; }}
        .header {{ display:flex; justify-content:space-between; align-items:center; border-bottom: 1px solid var(--border); padding-bottom: 1.5rem; margin-bottom: 2rem; }}
        .title-box h1 {{ font-size: 1.6rem; font-weight: 700; color: #fff; display:flex; align-items:center; gap:0.5rem; }}
        .badge-main {{ display:inline-block; padding: 0.35rem 0.85rem; border-radius: 9999px; font-size: 0.8rem; font-weight: 700; background: {status_badge_color}22; color: {status_badge_color}; border: 1px solid {status_badge_color}55; }}
        .grid {{ display:grid; grid-template-columns: 1fr 1.5fr; gap: 2rem; }}
        .card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 1.75rem; box-shadow: 0 10px 25px -5px rgba(0,0,0,0.5); }}
        .card h2 {{ font-size: 1.15rem; margin-bottom: 1.25rem; display:flex; justify-content:space-between; align-items:center; }}
        
        .prop-row {{ display:flex; justify-content:space-between; margin-bottom: 0.85rem; font-size: 0.95rem; border-bottom: 1px solid #1f293d44; padding-bottom: 0.4rem; }}
        .prop-val {{ font-weight:600; color: #f1f5f9; }}
        .alert-box {{ background: #ef444415; border: 1px solid #ef444455; color: #fca5a5; padding: 1rem; border-radius: 8px; font-size: 0.88rem; margin-top: 1rem; }}
        .success-box {{ background: #10b98115; border: 1px solid #10b98155; color: #6ee7b7; padding: 1rem; border-radius: 8px; font-size: 0.88rem; margin-top: 1rem; }}
        
        table {{ width:100%; border-collapse:collapse; font-size: 0.9rem; text-align:left; }}
        th {{ padding: 0.75rem 0.5rem; color: #94a3b8; font-size: 0.75rem; text-transform:uppercase; border-bottom: 1px solid var(--border); }}
        td {{ padding: 0.85rem 0.5rem; border-bottom: 1px solid #1e293b66; }}
        .badge-allow {{ background: #10b98122; color: #34d399; padding: 0.2rem 0.5rem; border-radius: 4px; font-weight:700; font-size:0.75rem; }}
        .badge-block {{ background: #ef444422; color: #f87171; padding: 0.2rem 0.5rem; border-radius: 4px; font-weight:700; font-size:0.75rem; }}
        .badge-warn  {{ background: #f59e0b22; color: #fbbf24; padding: 0.2rem 0.5rem; border-radius: 4px; font-weight:700; font-size:0.75rem; }}
        .refresh-btn {{ background: #2563eb; color:#fff; border:none; padding: 0.5rem 1rem; border-radius: 6px; cursor:pointer; font-weight:600; font-size:0.85rem; }}
        .refresh-btn:hover {{ background: #1d4ed8; }}
    </style>
</head>
<body>
    <div class="header">
        <div class="title-box">
            <h1>🛡️ Production Deployment Gateway</h1>
            <p style="color:#64748b; font-size:0.9rem; margin-top:0.3rem">Cryptographic Integrity Gate • Standard: NIST FIPS 204 ML-DSA-65 (Post-Quantum)</p>
        </div>
        <div>
            <span class="badge-main">{status_text}</span>
            <button class="refresh-btn" style="margin-left: 0.75rem" onclick="location.reload()">↻ Refresh</button>
        </div>
    </div>

    <div class="grid">
        <!-- Live Production Cluster Node -->
        <div class="card">
            <h2>
                <span>🖥️ Target Production Environment</span>
                <span style="font-size:0.8rem; color:#10b981">Node: prod-east-01</span>
            </h2>
            
            <div class="prop-row">
                <span style="color:#94a3b8">Active Artifact:</span>
                <span class="prop-val">{html.escape(art['name'])}</span>
            </div>
            <div class="prop-row">
                <span style="color:#94a3b8">Deployed Version:</span>
                <span class="prop-val" style="color:#38bdf8">{html.escape(art['version'])}</span>
            </div>
            <div class="prop-row">
                <span style="color:#94a3b8">Deployment Status:</span>
                <span class="prop-val">{html.escape(art['status'])}</span>
            </div>
            <div class="prop-row">
                <span style="color:#94a3b8">Cryptographic Gate:</span>
                <span class="prop-val" style="color:#10b981">{html.escape(art['signature_state'])}</span>
            </div>
            <div class="prop-row">
                <span style="color:#94a3b8">Artifact SHA-256:</span>
                <span class="prop-val" style="font-size:0.75rem; color:#94a3b8; font-family:monospace">{html.escape(art['sha256'][:28])}...</span>
            </div>

            {"<div class='alert-box'><strong>🚨 SUPPLY-CHAIN COMPROMISE DETECTED:</strong><br>" + html.escape(str(art['compromise_details'])) + "</div>" if is_compromised else ""}
            {"" if is_compromised else "<div class='success-box'><strong>✓ Production Integrity Verified:</strong> Active release validated against trusted root public key. Cryptographic lattice proof intact.</div>"}
            
            <p style="color:#475569; font-size:0.75rem; margin-top:1.5rem">
                * Production node enforces Zero-Trust gate: Unsigned or modified packages are blocked at the perimeter.
            </p>
        </div>

        <!-- Deployment Audit Log -->
        <div class="card">
            <h2>
                <span>📜 Gateway Deployment Audit Logs</span>
                <span style="font-size:0.8rem; color:#38bdf8">Real-time Stream</span>
            </h2>
            <table>
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>Artifact</th>
                        <th>SHA-256 Hash</th>
                        <th>Decision</th>
                        <th>Security Reason</th>
                    </tr>
                </thead>
                <tbody>
                    {audit_rows}
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>"""


class DeploymentGateHandler(BaseHTTPRequestHandler):
    """HTTP Request Handler for Post-Quantum Deployment Gate & Web Dashboard."""

    protocol_version = "HTTP/1.1"
    algorithm: str = "ML-DSA-65"
    deploy_dir: Path = Path(tempfile.gettempdir()) / "pqc_deployments"

    def log_message(self, format, *args):
        pass

    def _send_html(self, html_content: str):
        body = html_content.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, code: int, data: dict):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def _read_json_body(self):
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return None
        return json.loads(self.rfile.read(length).decode("utf-8"))

    # ------------------------------------------------------------------ #
    # GET Endpoints
    # ------------------------------------------------------------------ #
    def do_GET(self):
        if self.path in ("/", "/dashboard"):
            self._send_html(render_checkout_html())
        elif self.path == "/audit":
            self._send_json(200, {"logs": _AUDIT_LOGS})
        elif self.path == "/health":
            self._send_json(200, {
                "status": "HEALTHY",
                "service": "PQC Production Deployment Gateway",
                "algorithm": self.algorithm,
                "public_key_registered": _REGISTERED_PUBLIC_KEY is not None,
            })
        else:
            self._send_json(404, {"error": "Not found"})

    # ------------------------------------------------------------------ #
    # POST Endpoints
    # ------------------------------------------------------------------ #
    def do_POST(self):
        try:
            if self.path == "/register-key":
                self._handle_register_key()
            elif self.path == "/deploy":
                self._handle_deploy()
            elif self.path == "/legacy-deploy":
                self._handle_legacy_deploy()
            elif self.path == "/reset":
                self._handle_reset()
            else:
                self._send_json(404, {"error": "Unknown endpoint"})
        except Exception as exc:
            logger.exception("Error handling POST request")
            self._send_json(500, {"decision": "BLOCK", "error": f"Server internal error: {exc}"})

    # ------------------------------------------------------------------ #
    # Reset to Clean State
    # ------------------------------------------------------------------ #
    def _handle_reset(self):
        global _CURRENT_ARTIFACT
        _CURRENT_ARTIFACT = {
            "name": "core-payment-service.bin",
            "version": "v1.0.0-GA",
            "status": "HEALTHY",
            "signature_state": "VERIFIED (NIST FIPS 204 ML-DSA-65)",
            "sha256": "8a3f91d20b7c44e91a0c8831ef5021a97d95f71c3b691faab07f557e16dfc7ab",
            "deployed_at": "Baseline Cluster Release",
            "compromised": False,
            "compromise_details": None,
        }
        _record_audit("SYSTEM_RESET", "cluster-node", "", "INFO", "Cluster restored to clean baseline verified release")
        console.print("[bold yellow]↺ System reset to clean initial state.[/bold yellow]")
        self._send_json(200, {"status": "RESET_SUCCESS", "message": "Server restored to clean baseline state."})

    # ------------------------------------------------------------------ #
    # Scenario 1: Legacy Deployment without PQC (Compromised build accepted)
    # ------------------------------------------------------------------ #
    def _handle_legacy_deploy(self):
        global _CURRENT_ARTIFACT
        payload = self._read_json_body() or {}
        artifact_b64 = payload.get("artifact_bytes", "")
        artifact_name = payload.get("artifact_name", "payment_bundle.py")

        if not artifact_b64:
            self._send_json(400, {"error": "Missing artifact_bytes"})
            return

        raw_bytes = base64.b64decode(artifact_b64)
        raw_code = raw_bytes.decode("utf-8", errors="replace")
        sha256 = compute_sha256(raw_bytes)

        is_poisoned = "ATTACKER_EXFIL_WALLET" in raw_code or "COMPROMISED" in raw_code
        _CURRENT_ARTIFACT = {
            "name": artifact_name,
            "version": "v2.1.0-POISONED" if is_poisoned else "v2.0.0-LEGACY",
            "status": "COMPROMISED (ACTIVE INTRUSION)" if is_poisoned else "HEALTHY",
            "signature_state": "UNVERIFIED (Legacy Deployment Bypass)",
            "sha256": sha256,
            "deployed_at": time.strftime("%H:%M:%S UTC"),
            "compromised": is_poisoned,
            "compromise_details": "Unauthorized telemetry hook injected during build. Diverting payment hashes." if is_poisoned else None,
        }

        _record_audit("LEGACY_UNVERIFIED_DEPLOY", artifact_name, sha256, "ALLOW", "Legacy pipeline accepted build without PQC verification")

        console.print(
            Panel(
                f"[bold red]⚠ LEGACY PIPELINE BYPASS ACTIVATED (NO PQC GATE)[/bold red]\n"
                f"Artifact : [yellow]{artifact_name}[/yellow]\n"
                f"Status   : [red]ACCEPTED BLINDLY WITHOUT CRYPTOGRAPHIC CHECK[/red]\n\n"
                f"[dim]If this build contained compromised dependencies, production is now infected![/dim]",
                title="[bold yellow]LEGACY DEPLOYMENT (VULNERABLE)[/bold yellow]",
                border_style="yellow",
                expand=False,
            )
        )

        self._send_json(200, {
            "decision": "ALLOW",
            "warning": "Deployed without PQC cryptographic gate. Vulnerable to supply chain tampering.",
            "artifact": artifact_name,
            "sha256": sha256
        })

    # ------------------------------------------------------------------ #
    # Scenario 2: Post-Quantum Cryptographic Gate (ML-DSA-65 Authoritative)
    # ------------------------------------------------------------------ #
    def _handle_register_key(self):
        global _REGISTERED_PUBLIC_KEY, _REGISTERED_KEY_INFO
        payload = self._read_json_body()
        if not payload or "public_key_b64" not in payload:
            self._send_json(400, {"error": "Missing public_key_b64"})
            return
        try:
            pub_bytes = base64.b64decode(payload["public_key_b64"])
        except Exception as exc:
            self._send_json(400, {"error": f"Invalid base64: {exc}"})
            return

        _REGISTERED_PUBLIC_KEY = pub_bytes
        _REGISTERED_KEY_INFO = {"source": "client_registration", "bytes": len(pub_bytes)}
        _record_audit("KEY_REGISTRATION", "public.key", compute_sha256(pub_bytes), "ALLOW", "ML-DSA-65 Root Public Key Registered")

        console.print(f"[bold green]{TICK} Registered trusted ML-DSA-65 public key ({len(pub_bytes):,} bytes)[/bold green]")
        self._send_json(200, {"status": "REGISTERED", "key_size_bytes": len(pub_bytes)})

    def _handle_deploy(self):
        global _REGISTERED_PUBLIC_KEY, _CURRENT_ARTIFACT

        if _REGISTERED_PUBLIC_KEY is None:
            self._send_json(412, {"decision": "BLOCK", "error": "No trusted public key registered."})
            return

        payload = self._read_json_body() or {}
        artifact_name = payload.get("artifact_name", "payment_bundle.py")
        artifact_b64 = payload.get("artifact_bytes", "")
        signature_b64 = payload.get("signature_bytes", "")

        if not artifact_b64 or not signature_b64:
            self._send_json(400, {"error": "Missing artifact or signature bytes"})
            return

        artifact_bytes = base64.b64decode(artifact_b64)
        signature_bytes = base64.b64decode(signature_b64)
        artifact_hash = compute_sha256(artifact_bytes)
        size_str = format_file_size(len(artifact_bytes))

        # Perform ML-DSA-65 lattice verification
        engine = get_crypto_engine(self.algorithm)
        is_valid = engine.verify(artifact_bytes, signature_bytes, _REGISTERED_PUBLIC_KEY)

        if is_valid:
            # Upgrade live production state
            _CURRENT_ARTIFACT = {
                "name": artifact_name,
                "version": "v2.0.0-PROD",
                "status": "HEALTHY",
                "signature_state": "VERIFIED (NIST FIPS 204 ML-DSA-65)",
                "sha256": artifact_hash,
                "deployed_at": time.strftime("%H:%M:%S UTC"),
                "compromised": False,
                "compromise_details": None,
            }
            _record_audit("PQC_SECURE_DEPLOY", artifact_name, artifact_hash, "ALLOW", "ML-DSA-65 signature verified. Production cluster updated.")

            console.print(
                Panel(
                    f"Artifact   : [cyan]{artifact_name}[/cyan] ({size_str})\n"
                    f"SHA-256    : [dim]{artifact_hash}[/dim]\n"
                    f"Algorithm  : [bold green]{self.algorithm}[/bold green] (NIST FIPS 204)\n\n"
                    f"[bold green]DEPLOYMENT DECISION: ACCEPTED (ALLOW)[/bold green]\n"
                    f"✓ Live production node updated securely.",
                    title=f"[bold green]{TICK} PRODUCTION GATE: APPROVED[/bold green]",
                    border_style="green",
                    expand=False,
                )
            )

            self._send_json(200, {
                "decision": "ALLOW",
                "status": "DEPLOYED",
                "artifact": artifact_name,
                "sha256": artifact_hash,
                "message": "ML-DSA-65 verified. Production updated.",
            })
        else:
            # Drop artifact & log security incident
            _record_audit("PQC_SECURITY_BLOCK", artifact_name, artifact_hash, "BLOCK", "Signature mismatch: Supply chain or bytecode modification detected")

            console.print(
                Panel(
                    f"Artifact   : [red]{artifact_name}[/red] ({size_str})\n"
                    f"SHA-256    : [dim]{artifact_hash}[/dim]\n"
                    f"Integrity  : [bold red]FAILED — ML-DSA-65 Verification Rejected[/bold red]\n\n"
                    f"[bold red]DEPLOYMENT DECISION: REJECTED (BLOCK 403)[/bold red]\n"
                    f"✗ Malicious dependency or altered code dropped. Live service untouched.",
                    title=f"[bold red]{CROSS} SECURITY ALERT: DEPLOYMENT BLOCKED[/bold red]",
                    border_style="red",
                    expand=False,
                )
            )

            self._send_json(403, {
                "decision": "BLOCK",
                "status": "REJECTED",
                "artifact": artifact_name,
                "sha256": artifact_hash,
                "error": "ML-DSA-65 signature mismatch. Unauthorized modification or poisoned dependency detected.",
            })


def run_deployment_server(
    port: int = 8080,
    host: str = "0.0.0.0",
    public_key_path: Path = None,
    deploy_dir: Path = None,
    algorithm: str = "ML-DSA-65",
):
    global _REGISTERED_PUBLIC_KEY, _REGISTERED_KEY_INFO

    DeploymentGateHandler.algorithm = algorithm
    if public_key_path and Path(public_key_path).exists():
        with open(public_key_path, "rb") as f:
            _REGISTERED_PUBLIC_KEY = f.read()
        _REGISTERED_KEY_INFO = {"source": "file", "path": str(public_key_path)}
        console.print(f"[bold green]{TICK}[/bold green] Public key loaded: [cyan]{public_key_path}[/cyan]")

    httpd = HTTPServer((host, port), DeploymentGateHandler)

    console.print(
        Panel(
            f"Host Address   : [bold cyan]{host}:{port}[/bold cyan]\n"
            f"Algorithm      : [bold green]{algorithm}[/bold green] (NIST FIPS 204)\n"
            f"Public Key     : {'[bold green]LOADED[/bold green]' if _REGISTERED_PUBLIC_KEY else '[yellow]WAITING for /register-key[/yellow]'}\n\n"
            f"[bold cyan]WEB DASHBOARD READY:[/bold cyan] Open [underline]http://localhost:{port}[/underline] in your browser!\n"
            f"[dim]Endpoints: GET / (Dashboard) | GET /audit | POST /deploy | POST /reset[/dim]",
            title="[bold cyan]PQC PRODUCTION DEPLOYMENT GATEWAY[/bold cyan]",
            border_style="cyan",
            expand=False,
        )
    )

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        console.print("\n[yellow]Shutting down server...[/yellow]")
        httpd.server_close()
