"""Utility functions for hashing, formatting, and terminal displays."""

import hashlib
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Tuple
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# Ensure UTF-8 output on Windows terminals
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

console = Console(highlight=False)
err_console = Console(stderr=True, highlight=False)

# Safe symbols for all console encodings
TICK = "✓"
CROSS = "✗"
WARN = "⚠"


def compute_sha256(data: bytes) -> str:
    """Compute hex SHA-256 digest of raw bytes."""
    return hashlib.sha256(data).hexdigest()


def compute_file_sha256(path: Path) -> str:
    """Compute hex SHA-256 digest of a file in chunks."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def format_file_size(size_bytes: int) -> str:
    """Format byte size into human readable string (e.g. 24.3 KB)."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    else:
        return f"{size_bytes / (1024 * 1024):.1f} MB"


def get_iso_timestamp() -> str:
    """Get current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


def render_keygen_success(pub_path: Path, priv_path: Path, algorithm: str):
    """Render key generation success message."""
    console.print(f"[bold green]{TICK}[/bold green] [bold]{algorithm}[/bold] key pair generated\n")
    console.print(f"Public key : [cyan]{pub_path}[/cyan]")
    console.print(f"Private key: [cyan]{priv_path}[/cyan]\n")
    console.print(f"[bold yellow]{WARN} Keep the private key secret.[/bold yellow]")
    console.print(f"[bold yellow]{WARN} Do not commit it to source control.[/bold yellow]")


def render_sign_summary(
    artifact_path: Path,
    algorithm: str,
    size_bytes: int,
    sha256_hash: str,
    signature_path: Path,
):
    """Render signing summary panel."""
    content = (
        f"Artifact   : [cyan]{artifact_path}[/cyan]\n"
        f"Algorithm  : [bold green]{algorithm}[/bold green]\n"
        f"Size       : {format_file_size(size_bytes)}\n"
        f"SHA-256    : [dim]{sha256_hash}[/dim]\n\n"
        f"[bold green]{TICK} Signature generated[/bold green]\n\n"
        f"Signature  : [cyan]{signature_path}[/cyan]"
    )
    panel = Panel(
        content,
        title="[bold cyan]PQC CODE SIGNER[/bold cyan]",
        title_align="left",
        border_style="cyan",
        expand=False,
    )
    console.print(panel)


def render_verify_valid(algorithm: str, details: List[str] = None):
    """Render verification VALID result with deployment decision."""
    content = (
        "Artifact integrity : [bold green]VERIFIED[/bold green]\n"
        "Signer verification: [bold green]PASSED[/bold green]\n"
        f"Algorithm          : [bold]{algorithm}[/bold]\n\n"
        "──────────────────────────────\n"
        "[bold green]DEPLOYMENT DECISION: ALLOW[/bold green]\n"
        "──────────────────────────────\n\n"
        "[bold green]ACTION:[/bold green]\n"
        f"[bold green]{TICK} Deployment may proceed.[/bold green]"
    )
    panel = Panel(
        content,
        title=f"[bold green]{TICK} SIGNATURE VALID[/bold green]",
        title_align="center",
        border_style="green",
        expand=False,
    )
    console.print(panel)


def render_verify_invalid(algorithm: str, possible_causes: List[str] = None):
    """Render verification INVALID result with deployment blocking."""
    causes = possible_causes or [
        "Artifact was modified after signing",
        "Signature is invalid or corrupted",
        "Wrong public key was supplied",
    ]
    causes_formatted = "\n".join(f"• {cause}" for cause in causes)

    content = (
        "Artifact integrity : [bold red]FAILED[/bold red]\n"
        "Signer verification: [bold red]FAILED[/bold red]\n"
        f"Algorithm          : [bold]{algorithm}[/bold]\n\n"
        "Possible causes:\n"
        f"[yellow]{causes_formatted}[/yellow]\n\n"
        "──────────────────────────────\n"
        "[bold red]DEPLOYMENT DECISION: BLOCK[/bold red]\n"
        "──────────────────────────────\n\n"
        "[bold red]ACTION:[/bold red]\n"
        f"[bold red]{CROSS} BLOCK DEPLOYMENT[/bold red]"
    )
    panel = Panel(
        content,
        title=f"[bold red]{CROSS} SIGNATURE INVALID[/bold red]",
        title_align="center",
        border_style="red",
        expand=False,
    )
    console.print(panel)


def render_demo_table(results: List[Tuple[str, bool]]):
    """Render evaluation table for demo run."""
    table = Table(
        title="DEMO EVALUATION",
        title_style="bold cyan",
        header_style="bold magenta",
        border_style="cyan",
        expand=False,
    )
    table.add_column("Test", style="bold", min_width=28)
    table.add_column("Result", justify="center", min_width=10)

    passed_count = 0
    for name, success in results:
        if success:
            passed_count += 1
            table.add_row(name, "[bold green]PASS[/bold green]")
        else:
            table.add_row(name, "[bold red]FAIL[/bold red]")

    total = len(results)
    pct = (passed_count / total * 100) if total > 0 else 0

    table.add_section()
    table.add_row("Detection rate", f"[bold green]{pct:.0f}%[/bold green]")
    table.add_row("Tests passed", f"[bold green]{passed_count}/{total}[/bold green]")

    console.print()
    console.print(table)
    console.print("\n[dim]Note: Basic functional evaluation/demo. Not a statistical security benchmark.[/dim]\n")
