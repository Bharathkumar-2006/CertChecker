"""
Shared utility functions: display helpers, Rich rendering, formatting.
"""

import datetime
from typing import Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box
from rich.columns import Columns
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

console = Console()


# ─── Threshold constants ────────────────────────────────────────────────────

CRITICAL_DAYS = 7
WARNING_DAYS = 30
GOOD_DAYS = 90


def days_color(days: int, is_expired: bool = False) -> str:
    """Return a Rich color string for a days-remaining value."""
    if is_expired:
        return "bold red"
    if days <= CRITICAL_DAYS:
        return "bold orange1"
    if days <= WARNING_DAYS:
        return "bold yellow"
    if days <= GOOD_DAYS:
        return "bold cyan"
    return "bold green"


def days_icon(days: int, is_expired: bool = False) -> str:
    """Return an emoji icon for a days-remaining value."""
    if is_expired:
        return "💀"
    if days <= CRITICAL_DAYS:
        return "🚨"
    if days <= WARNING_DAYS:
        return "⚠️ "
    if days <= GOOD_DAYS:
        return "🔔"
    return "✅"


def bool_icon(value: bool, invert: bool = False) -> str:
    """Return ✅/❌ for a boolean, optionally inverting the meaning."""
    if invert:
        return "✅" if not value else "❌"
    return "✅" if value else "❌"


def render_cert_panel(result: dict) -> None:
    """Render a full certificate panel with rich styling."""
    hostname = result.get("hostname", "")
    port = result.get("port", 443)
    days = result.get("days_remaining", 0)
    is_expired = result.get("is_expired", False)
    is_valid = result.get("is_valid", False)

    color = days_color(days, is_expired)
    icon = days_icon(days, is_expired)

    # ── Header status ──
    if is_expired:
        status_str = f"[bold red]CERTIFICATE EXPIRED[/bold red]"
    elif days <= CRITICAL_DAYS:
        status_str = f"[bold orange1]CRITICAL — Expires in {days} days[/bold orange1]"
    elif days <= WARNING_DAYS:
        status_str = f"[bold yellow]WARNING — Expires in {days} days[/bold yellow]"
    else:
        status_str = f"[bold green]VALID — Expires in {days} days[/bold green]"

    console.print()
    console.rule(f"[bold blue]🔒 {hostname}:{port}[/bold blue]")
    console.print(f"  {icon}  {status_str}")
    console.print()

    # ── Overview table ──
    subject = result.get("subject", {})
    issuer = result.get("issuer", {})

    overview = Table(box=box.ROUNDED, show_header=False, padding=(0, 1), border_style="blue")
    overview.add_column("Field", style="bold cyan", width=22)
    overview.add_column("Value", style="white")

    overview.add_row("Hostname", f"[bold]{hostname}[/bold]")
    overview.add_row("Resolved IP", result.get("resolved_ip", "—"))
    overview.add_row("Port", str(port))
    overview.add_row("TLS Version", result.get("tls_version") or "—")
    overview.add_row("Cipher Suite", result.get("cipher_suite") or "—")
    overview.add_row("Cipher Bits", str(result.get("cipher_bits") or "—"))
    console.print(overview)
    console.print()

    # ── Validity table ──
    validity = Table(title="📅 Validity", box=box.ROUNDED, title_style="bold magenta", border_style="magenta", padding=(0, 1))
    validity.add_column("Field", style="bold cyan")
    validity.add_column("Value")

    validity.add_row("Not Before", result.get("not_before", "—"))
    validity.add_row("Not After", Text(result.get("not_after", "—"), style=color))
    validity.add_row("Days Remaining", Text(str(days), style=color))
    validity.add_row("Status", Text("EXPIRED" if is_expired else ("VALID" if is_valid else "INVALID"),
                                    style="red" if is_expired else ("green" if is_valid else "yellow")))
    console.print(validity)
    console.print()

    # ── Subject / Issuer ──
    identity = Table(title="🪪 Identity", box=box.ROUNDED, title_style="bold cyan", border_style="cyan", padding=(0, 1))
    identity.add_column("", style="bold cyan")
    identity.add_column("Subject")
    identity.add_column("Issuer")

    fields = ["CN", "O", "OU", "C", "ST", "L"]
    for f in fields:
        sv = subject.get(f, "—")
        iv = issuer.get(f, "—")
        if sv != "—" or iv != "—":
            identity.add_row(f, sv, iv)
    identity.add_row("Self-Signed", bool_icon(result.get("is_self_signed", False), invert=True), "")
    console.print(identity)
    console.print()

    # ── Key / Signature ──
    key_tbl = Table(title="🔑 Key & Signature", box=box.ROUNDED, title_style="bold yellow", border_style="yellow", padding=(0, 1))
    key_tbl.add_column("Field", style="bold cyan")
    key_tbl.add_column("Value")

    key_type = result.get("key_type", "—")
    key_bits = result.get("key_bits", "—")
    curve = result.get("key_curve")
    key_str = f"{key_type} {key_bits}-bit" + (f" ({curve})" if curve else "")
    sig_algo = result.get("signature_algorithm", "—")
    is_weak_sig = result.get("is_weak_signature", False)

    key_tbl.add_row("Key Algorithm", key_str)
    key_tbl.add_row("Serial Number", result.get("serial_number", "—"))
    sig_text = Text(sig_algo)
    if is_weak_sig:
        sig_text.stylize("bold red")
        sig_text.append(" ⚠  WEAK", style="bold red")
    key_tbl.add_row("Signature Algo", sig_text)
    key_tbl.add_row("SHA-256 Fingerprint", Text(result.get("fingerprint_sha256", "—")[:47] + "...", style="dim"))
    key_tbl.add_row("SHA-1 Fingerprint", Text(result.get("fingerprint_sha1", "—")[:47] + "...", style="dim"))
    console.print(key_tbl)
    console.print()

    # ── SANs ──
    sans = result.get("sans", [])
    if sans:
        san_tbl = Table(title=f"🌐 Subject Alternative Names ({len(sans)})", box=box.SIMPLE, title_style="bold blue", border_style="blue")
        san_tbl.add_column("SAN")
        for san in sans:
            san_tbl.add_row(san)
        console.print(san_tbl)
        console.print()

    # ── Key Usage ──
    ku = result.get("key_usage", [])
    eku = result.get("extended_key_usage", [])
    if ku or eku:
        usage_tbl = Table(title="🔐 Key Usage", box=box.SIMPLE, title_style="bold cyan", border_style="cyan")
        usage_tbl.add_column("Type")
        usage_tbl.add_column("Values")
        if ku:
            usage_tbl.add_row("Key Usage", ", ".join(ku))
        if eku:
            usage_tbl.add_row("Extended Key Usage", ", ".join(eku))
        console.print(usage_tbl)
        console.print()

    # ── OCSP / CRL ──
    ocsp = result.get("ocsp_urls", [])
    crl = result.get("crl_urls", [])
    if ocsp or crl:
        revoke_tbl = Table(title="🔄 Revocation", box=box.SIMPLE, title_style="bold white", border_style="dim")
        revoke_tbl.add_column("Type")
        revoke_tbl.add_column("URL")
        for url in ocsp:
            revoke_tbl.add_row("OCSP", url)
        for url in crl:
            revoke_tbl.add_row("CRL", url)
        console.print(revoke_tbl)
        console.print()

    # ── Weaknesses / Alerts ──
    weaknesses = result.get("weaknesses", [])
    if weaknesses:
        w_panel = Panel(
            "\n".join(f"  🚨 {w}" for w in weaknesses),
            title="[bold red]⚠  Security Issues Detected[/bold red]",
            border_style="red",
        )
        console.print(w_panel)
        console.print()
    else:
        console.print(Panel(
            "  ✅  No known weaknesses detected.",
            title="[bold green]Security Analysis[/bold green]",
            border_style="green",
        ))
        console.print()


def render_summary_table(results: list, warn_days: int = WARNING_DAYS, critical_days: int = CRITICAL_DAYS) -> None:
    """Render a compact summary table for multiple results."""
    tbl = Table(
        title="🔒 SSL Certificate Summary",
        box=box.ROUNDED,
        title_style="bold blue",
        border_style="blue",
        show_lines=True,
    )
    tbl.add_column("Host", style="bold white", no_wrap=True)
    tbl.add_column("Status", justify="center")
    tbl.add_column("Days Left", justify="right")
    tbl.add_column("Expires", justify="center")
    tbl.add_column("Subject CN", no_wrap=False)
    tbl.add_column("Issuer", no_wrap=False)
    tbl.add_column("TLS Ver", justify="center")
    tbl.add_column("Key", justify="center")
    tbl.add_column("Issues", justify="center")

    for r in results:
        if "error" in r:
            tbl.add_row(
                r.get("hostname", ""),
                Text("ERROR", style="bold red"),
                "—", "—", "—", "—", "—", "—",
                Text("⚠", style="red"),
            )
            continue

        days = r.get("days_remaining", 0)
        is_expired = r.get("is_expired", False)
        color = days_color(days, is_expired)
        icon = days_icon(days, is_expired)

        if is_expired:
            status = Text("EXPIRED", style="bold red")
        elif days <= critical_days:
            status = Text(f"CRITICAL", style="bold orange1")
        elif days <= warn_days:
            status = Text("WARNING", style="bold yellow")
        else:
            status = Text("VALID", style="bold green")

        subject = r.get("subject", {})
        issuer = r.get("issuer", {})
        weaknesses = r.get("weaknesses", [])
        issues_icon = Text(f"⚠ {len(weaknesses)}", style="red") if weaknesses else Text("✓", style="green")

        tbl.add_row(
            f"{r.get('hostname', '')}:{r.get('port', 443)}",
            status,
            Text(f"{icon} {days}d", style=color),
            r.get("not_after", "—"),
            subject.get("CN", subject.get("O", "—")),
            issuer.get("CN", issuer.get("O", "—")),
            r.get("tls_version") or "—",
            f"{r.get('key_type', '?')} {r.get('key_bits', '?')}b",
            issues_icon,
        )

    console.print(tbl)


def make_progress() -> Progress:
    """Create a styled Rich progress bar."""
    return Progress(
        SpinnerColumn(style="blue"),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=30, style="blue", complete_style="green"),
        TextColumn("[bold white]{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
    )
