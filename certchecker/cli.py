"""
CertChecker CLI — Main entrypoint.
All CLI commands are defined here using Click.
"""

import sys
import os
import json
import click
import datetime
from typing import Optional
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich.columns import Columns
from rich import box
from rich.rule import Rule

from certchecker.checker import get_certificate, CertCheckError
from certchecker.chain import get_certificate_chain
from certchecker.http_checks import run_http_checks, scan_tls_ports
from certchecker.reporter import export_json, export_csv, export_html
from certchecker.monitor import monitor_domains, get_alert_color
from certchecker.utils import (
    console,
    render_cert_panel,
    render_summary_table,
    make_progress,
    days_color,
    days_icon,
    bool_icon,
    WARNING_DAYS,
    CRITICAL_DAYS,
)

# ─── ASCII banner ─────────────────────────────────────────────────────────────

BANNER = r"""
[bold blue]
   ██████╗███████╗██████╗ ████████╗ ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗███████╗██████╗[/bold blue]
[blue]  ██╔════╝██╔════╝██╔══██╗╚══██╔══╝██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝██╔════╝██╔══██╗[/blue]
[cyan]  ██║     █████╗  ██████╔╝   ██║   ██║     ███████║█████╗  ██║     █████╔╝ █████╗  ██████╔╝[/cyan]
[bright_cyan]  ██║     ██╔══╝  ██╔══██╗   ██║   ██║     ██╔══██║██╔══╝  ██║     ██╔═██╗ ██╔══╝  ██╔══██╗[/bright_cyan]
[white]  ╚██████╗███████╗██║  ██║   ██║   ╚██████╗██║  ██║███████╗╚██████╗██║  ██╗███████╗██║  ██║[/white]
[dim]   ╚═════╝╚══════╝╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝[/dim]
"""


# ─── Main group ───────────────────────────────────────────────────────────────

@click.group(invoke_without_command=True)
@click.version_option("1.0.0", prog_name="certchecker")
@click.pass_context
def cli(ctx):
    """
    \b
    🔒 CertChecker — SSL/TLS Certificate Inspection Tool

    Inspect, monitor, and report on SSL/TLS certificates with ease.
    Run 'certchecker COMMAND --help' for detailed usage on any command.
    """
    if ctx.invoked_subcommand is None:
        console.print(BANNER)
        console.print(Panel(
            "[cyan]Usage:[/cyan] [bold white]certchecker [COMMAND] [OPTIONS][/bold white]\n\n"
            "Run [bold green]certchecker --help[/bold green] to see all commands.",
            title="[bold blue]🔒 CertChecker[/bold blue]",
            border_style="blue",
        ))


# ─── check ────────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("hostname")
@click.option("-p", "--port", default=443, show_default=True, help="TCP port to connect on.")
@click.option("-t", "--timeout", default=10, show_default=True, help="Connection timeout in seconds.")
@click.option("--warn-days", default=WARNING_DAYS, show_default=True, help="Days threshold for WARNING.")
@click.option("--critical-days", default=CRITICAL_DAYS, show_default=True, help="Days threshold for CRITICAL.")
@click.option("--json", "as_json", is_flag=True, help="Output raw JSON instead of formatted display.")
@click.option("--no-http", is_flag=True, help="Skip HTTP-level checks (HSTS, redirects, headers).")
@click.option("-o", "--output", default=None, help="Save output to a file (use with --json).")
def check(hostname, port, timeout, warn_days, critical_days, as_json, no_http, output):
    """
    Inspect the SSL certificate for a single HOSTNAME.

    You can pass a plain domain or a full URL — the scheme is stripped automatically.

    \b
    Examples:
      certchecker check google.com
      certchecker check https://github.com
      certchecker check github.com --port 443 --json
      certchecker check example.com --warn-days 60 --critical-days 14
    """
    # Strip URL scheme if user passes https://domain or http://domain
    for prefix in ("https://", "http://"):
        if hostname.lower().startswith(prefix):
            hostname = hostname[len(prefix):].rstrip("/")
            break
    if not as_json:
        console.print(BANNER)
        console.print(f"[dim]Connecting to [bold]{hostname}:{port}[/bold]…[/dim]")
        console.print()

    # Fetch certificate
    try:
        with console.status(f"[blue]Fetching certificate from {hostname}:{port}…", spinner="dots"):
            result = get_certificate(hostname, port=port, timeout=timeout)
    except CertCheckError as e:
        if as_json:
            click.echo(json.dumps({"hostname": hostname, "port": port, "error": str(e)}, indent=2))
        else:
            console.print(Panel(
                f"[bold red]Error:[/bold red] {e}",
                title=f"[red]❌ Failed — {hostname}[/red]",
                border_style="red",
            ))
        sys.exit(1)

    # HTTP checks
    http_result = None
    if not no_http:
        try:
            with console.status("[blue]Running HTTP security checks…", spinner="dots"):
                http_result = run_http_checks(hostname, port=port, timeout=timeout)
        except Exception:
            pass

    if as_json:
        full = {"certificate": result}
        if http_result:
            full["http"] = http_result
        out_str = json.dumps(full, indent=2, default=str)
        if output:
            with open(output, "w") as f:
                f.write(out_str)
            console.print(f"[green]Saved to {output}[/green]")
        else:
            click.echo(out_str)
        return

    # Rich display
    render_cert_panel(result)

    # HTTP section
    if http_result:
        _render_http_panel(http_result)


# ─── helpers shared by bulk/monitor/report ────────────────────────────────────

def _resolve_hostnames(hostnames_args: tuple, file: str) -> list:
    """
    Resolve the final list of hostnames from CLI args and/or a --file.
    Strips http:// / https:// from any entries automatically.
    Raises click.UsageError if neither source is provided.
    """
    if hostnames_args and file:
        raise click.UsageError("Provide either HOSTNAME(s) as arguments OR --file, not both.")

    def _clean(h: str) -> str:
        h = h.strip()
        for prefix in ("https://", "http://"):
            if h.lower().startswith(prefix):
                h = h[len(prefix):].rstrip("/")
                break
        return h

    if hostnames_args:
        return [_clean(h) for h in hostnames_args if h.strip()]

    if file:
        with open(file, "r") as f:
            return [
                _clean(line) for line in f
                if line.strip() and not line.strip().startswith("#")
            ]

    raise click.UsageError(
        "No domains provided. Pass hostnames as arguments or use --file.\n\n"
        "  Example: certchecker bulk google.com github.com\n"
        "  Example: certchecker bulk --file domains.txt"
    )


# ─── bulk ─────────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("hostnames", nargs=-1)
@click.option("-f", "--file", "file", default=None, type=click.Path(exists=True),
              help="Read hostnames from a file (one per line).")
@click.option("-p", "--port", default=443, show_default=True, help="TCP port to connect on.")
@click.option("-t", "--timeout", default=10, show_default=True, help="Connection timeout in seconds.")
@click.option("--warn-days", default=WARNING_DAYS, show_default=True, help="Days threshold for WARNING.")
@click.option("--critical-days", default=CRITICAL_DAYS, show_default=True, help="Days threshold for CRITICAL.")
@click.option("--format", "fmt", type=click.Choice(["table", "json", "csv", "html"]), default="table", show_default=True)
@click.option("-o", "--output", default=None, help="Save report to this file path.")
@click.option("--fail-on-expired", is_flag=True, help="Exit with code 1 if any cert is expired.")
@click.option("--fail-on-warning", is_flag=True, help="Exit with code 1 if any cert is in warning state.")
def bulk(hostnames, file, port, timeout, warn_days, critical_days, fmt, output, fail_on_expired, fail_on_warning):
    """
    Check SSL certificates for one or more domains.

    Pass hostnames directly as arguments, or use --file to read from a file.
    Lines starting with '#' in the file are treated as comments.

    \b
    Examples:
      certchecker bulk google.com github.com
      certchecker bulk google.com github.com --format html -o report.html
      certchecker bulk --file domains.txt
      certchecker bulk --file domains.txt --format json -o results.json
      certchecker bulk google.com --fail-on-expired
    """
    try:
        hostname_list = _resolve_hostnames(hostnames, file)
    except click.UsageError as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        sys.exit(1)

    if not hostname_list:
        console.print("[red]No valid hostnames found.[/red]")
        sys.exit(1)

    if fmt == "table":
        console.print(BANNER)

    results = []
    progress = make_progress()

    with progress:
        task = progress.add_task(f"Checking {len(hostname_list)} domain(s)…", total=len(hostname_list))
        for hostname in hostname_list:
            progress.update(task, description=f"[cyan]Checking {hostname}…")
            try:
                result = get_certificate(hostname, port=port, timeout=timeout)
            except CertCheckError as e:
                result = {
                    "hostname": hostname,
                    "port": port,
                    "error": str(e),
                    "is_valid": False,
                    "is_expired": False,
                    "days_remaining": 0,
                    "subject": {},
                    "issuer": {},
                    "weaknesses": [str(e)],
                }
            results.append(result)
            progress.advance(task)

    # Output
    if fmt == "table":
        console.print()
        render_summary_table(results, warn_days=warn_days, critical_days=critical_days)
        _print_bulk_stats(results, warn_days, critical_days)
    elif fmt == "json":
        out = export_json(results, output_path=output)
        if not output:
            click.echo(out)
    elif fmt == "csv":
        out = export_csv(results, output_path=output)
        if not output:
            click.echo(out)
    elif fmt == "html":
        out = export_html(results, output_path=output)
        if not output:
            click.echo(out)

    if output:
        console.print(f"\n[bold green]✅ Report saved to:[/bold green] {output}")

    # Exit codes
    if fail_on_expired and any(r.get("is_expired") for r in results):
        sys.exit(1)
    if fail_on_warning and any(
        not r.get("is_expired") and r.get("days_remaining", 999) <= warn_days
        for r in results
    ):
        sys.exit(1)


# ─── chain ────────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("hostname")
@click.option("-p", "--port", default=443, show_default=True, help="TCP port.")
@click.option("-t", "--timeout", default=10, show_default=True, help="Connection timeout.")
@click.option("--json", "as_json", is_flag=True, help="Output raw JSON.")
def chain(hostname, port, timeout, as_json):
    """
    Display the full certificate chain for HOSTNAME.

    Shows leaf → intermediate → root CA hierarchy.

    \b
    Examples:
      certchecker chain google.com
      certchecker chain github.com --json
    """
    if not as_json:
        console.print(BANNER)

    try:
        with console.status(f"[blue]Fetching certificate chain from {hostname}:{port}…", spinner="dots"):
            chain_certs = get_certificate_chain(hostname, port=port, timeout=timeout)
    except RuntimeError as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)

    if as_json:
        click.echo(json.dumps(chain_certs, indent=2, default=str))
        return

    console.print()
    console.rule(f"[bold blue]🔗 Certificate Chain — {hostname}:{port}[/bold blue]")
    console.print()

    for i, cert in enumerate(chain_certs):
        is_last = i == len(chain_certs) - 1
        prefix = "  " * i
        connector = "└─" if is_last else "├─"

        days = cert.get("days_remaining", "?")
        color = days_color(days if isinstance(days, int) else 9999)
        icon = days_icon(days if isinstance(days, int) else 9999)

        role = cert.get("role", "Unknown")
        subject_cn = cert.get("subject_cn", "Unknown")
        issuer_cn = cert.get("issuer_cn", "Unknown")

        tbl = Table(
            title=f"{prefix}{connector} [{i}] {icon} {role}",
            box=box.SIMPLE_HEAD,
            title_style=f"bold {'white' if i == 0 else 'cyan' if not is_last else 'yellow'}",
            show_header=True,
            header_style="dim",
            border_style="blue" if i == 0 else "dim",
        )
        tbl.add_column("Field", style="cyan", width=20)
        tbl.add_column("Value")
        tbl.add_row("Subject CN", f"[bold]{subject_cn}[/bold]")
        tbl.add_row("Issued By", issuer_cn)
        tbl.add_row("Expires", cert.get("not_after", "—"))
        tbl.add_row("Days Remaining", Text(str(days), style=color))
        tbl.add_row("Is CA", bool_icon(cert.get("is_ca", False)))
        tbl.add_row("Self-Signed", bool_icon(cert.get("is_self_signed", False), invert=True))
        fp = cert.get("sha256_fingerprint", "")
        tbl.add_row("SHA-256 (partial)", fp[:47] + "…" if fp else "—")
        console.print(tbl)
        if not is_last:
            console.print(f"{prefix}  │")

    console.print()


# ─── monitor ──────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("hostnames", nargs=-1)
@click.option("-f", "--file", "file", default=None, type=click.Path(exists=True),
              help="Read hostnames from a file (one per line).")
@click.option("-p", "--port", default=443, show_default=True, help="TCP port.")
@click.option("-t", "--timeout", default=10, show_default=True, help="Connection timeout (seconds).")
@click.option("-i", "--interval", default=3600, show_default=True, help="Polling interval in seconds.")
@click.option("--warn-days", default=WARNING_DAYS, show_default=True, help="Warning threshold (days).")
@click.option("--critical-days", default=CRITICAL_DAYS, show_default=True, help="Critical threshold (days).")
@click.option("--alert-only", is_flag=True, help="Only print alerts (warning/critical/expired), not OK.")
def monitor(hostnames, file, port, timeout, interval, warn_days, critical_days, alert_only):
    """
    Continuously monitor SSL certificates for one or more domains.

    Pass hostnames directly as arguments, or use --file to read from a file.
    Press Ctrl+C to stop. Polls each domain every INTERVAL seconds.

    \b
    Examples:
      certchecker monitor google.com github.com
      certchecker monitor google.com --interval 300 --warn-days 60
      certchecker monitor --file domains.txt --alert-only
    """
    try:
        hostname_list = _resolve_hostnames(hostnames, file)
    except click.UsageError as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        sys.exit(1)

    if not hostname_list:
        console.print("[red]No valid hostnames found.[/red]")
        sys.exit(1)

    console.print(BANNER)
    console.print(Panel(
        f"[cyan]Monitoring [bold]{len(hostname_list)}[/bold] domain(s)\n"
        f"Interval: [bold]{interval}s[/bold]  |  "
        f"Warn: [yellow]{warn_days}d[/yellow]  |  "
        f"Critical: [red]{critical_days}d[/red]\n\n"
        f"Press [bold]Ctrl+C[/bold] to stop.",
        title="[bold blue]🔁 Monitor Mode[/bold blue]",
        border_style="blue",
    ))

    def on_result(result):
        level = result.get("alert_level", "OK")
        h = result.get("hostname", "?")
        days = result.get("days_remaining", "?")
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        color = get_alert_color(level)

        if alert_only and level == "OK":
            return

        if "error" in result:
            msg = f"[dim]{ts}[/dim]  [{color}]{level:8}[/{color}]  [white]{h}[/white]  [red]{result['error']}[/red]"
        else:
            not_after = result.get("not_after", "—")
            msg = (
                f"[dim]{ts}[/dim]  [{color}]{level:8}[/{color}]  "
                f"[white]{h}[/white]  "
                f"[{days_color(days if isinstance(days, int) else 999)}]{days}d remaining[/]  "
                f"[dim]expires {not_after}[/dim]"
            )
        console.print(msg)

    try:
        monitor_domains(
            hostnames=hostname_list,
            port=port,
            interval=interval,
            warn_days=warn_days,
            critical_days=critical_days,
            timeout=timeout,
            on_result=on_result,
        )
    except KeyboardInterrupt:
        console.print("\n[yellow]Monitor stopped.[/yellow]")


# ─── compare ──────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("hostname_a")
@click.argument("hostname_b")
@click.option("-p", "--port", default=443, show_default=True, help="TCP port.")
@click.option("-t", "--timeout", default=10, show_default=True, help="Connection timeout.")
@click.option("--json", "as_json", is_flag=True, help="Output raw JSON.")
def compare(hostname_a, hostname_b, port, timeout, as_json):
    """
    Compare SSL certificates of two domains side-by-side.

    \b
    Examples:
      certchecker compare google.com microsoft.com
      certchecker compare github.com gitlab.com --json
    """
    if not as_json:
        console.print(BANNER)

    results = {}
    for hostname in [hostname_a, hostname_b]:
        try:
            with console.status(f"[blue]Fetching {hostname}…", spinner="dots"):
                results[hostname] = get_certificate(hostname, port=port, timeout=timeout)
        except CertCheckError as e:
            results[hostname] = {"hostname": hostname, "error": str(e)}

    if as_json:
        click.echo(json.dumps(results, indent=2, default=str))
        return

    ra = results[hostname_a]
    rb = results[hostname_b]

    console.print()
    console.rule(f"[bold blue]⚖  Compare: {hostname_a}  vs  {hostname_b}[/bold blue]")
    console.print()

    fields = [
        ("Status", lambda r: "VALID" if r.get("is_valid") else "INVALID/EXPIRED"),
        ("Days Remaining", lambda r: str(r.get("days_remaining", "—"))),
        ("Not After", lambda r: r.get("not_after", "—")),
        ("Subject CN", lambda r: r.get("subject", {}).get("CN", "—")),
        ("Subject O", lambda r: r.get("subject", {}).get("O", "—")),
        ("Issuer CN", lambda r: r.get("issuer", {}).get("CN", "—")),
        ("TLS Version", lambda r: r.get("tls_version", "—")),
        ("Cipher Suite", lambda r: r.get("cipher_suite", "—")),
        ("Key", lambda r: f"{r.get('key_type','?')} {r.get('key_bits','?')}b"),
        ("Signature Algo", lambda r: r.get("signature_algorithm", "—")),
        ("Self-Signed", lambda r: "Yes" if r.get("is_self_signed") else "No"),
        ("SANs Count", lambda r: str(len(r.get("sans", [])))),
        ("Weaknesses", lambda r: str(len(r.get("weaknesses", [])))),
        ("SHA-256 (partial)", lambda r: r.get("fingerprint_sha256", "")[:32] + "…"),
    ]

    tbl = Table(
        box=box.ROUNDED,
        show_header=True,
        border_style="blue",
        header_style="bold cyan",
    )
    tbl.add_column("Field", style="bold cyan", width=20)
    tbl.add_column(hostname_a, style="white", width=32)
    tbl.add_column(hostname_b, style="white", width=32)
    tbl.add_column("Match", justify="center", width=7)

    for label, extractor in fields:
        va = extractor(ra) if "error" not in ra else "[red]ERROR[/red]"
        vb = extractor(rb) if "error" not in rb else "[red]ERROR[/red]"
        match_icon = "✅" if va == vb else "❌"

        # Colorize days remaining
        if label == "Days Remaining":
            try:
                days_a = int(va)
                va_text = Text(va, style=days_color(days_a, ra.get("is_expired", False)))
            except (ValueError, TypeError):
                va_text = Text(va)
            try:
                days_b = int(vb)
                vb_text = Text(vb, style=days_color(days_b, rb.get("is_expired", False)))
            except (ValueError, TypeError):
                vb_text = Text(vb)
            tbl.add_row(label, va_text, vb_text, match_icon)
        else:
            tbl.add_row(label, va, vb, match_icon)

    console.print(tbl)
    console.print()


# ─── scan ─────────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("hostname")
@click.option("-t", "--timeout", default=5, show_default=True, help="Port scan timeout.")
@click.option("--json", "as_json", is_flag=True, help="Output raw JSON.")
def scan(hostname, timeout, as_json):
    """
    Scan TLS-capable ports and inspect security headers on HOSTNAME.

    \b
    Examples:
      certchecker scan example.com
      certchecker scan api.example.com --json
    """
    if not as_json:
        console.print(BANNER)

    with console.status(f"[blue]Scanning {hostname}…", spinner="dots"):
        port_results = scan_tls_ports(hostname, timeout=timeout)
        http_result = run_http_checks(hostname, timeout=timeout)

    if as_json:
        click.echo(json.dumps({"ports": port_results, "http": http_result}, indent=2, default=str))
        return

    console.print()
    console.rule(f"[bold blue]🔍 Scan Results — {hostname}[/bold blue]")
    console.print()

    # Port table
    port_tbl = Table(title="🔌 TLS Port Scan", box=box.ROUNDED, title_style="bold blue", border_style="blue")
    port_tbl.add_column("Port", justify="right", style="cyan")
    port_tbl.add_column("Service")
    port_tbl.add_column("Status", justify="center")

    for pr in port_results:
        status = Text("OPEN", style="bold green") if pr["open"] else Text("closed", style="dim red")
        port_tbl.add_row(str(pr["port"]), pr["service"], status)

    console.print(port_tbl)
    console.print()

    _render_http_panel(http_result)


# ─── report ───────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("hostnames", nargs=-1)
@click.option("-f", "--file", "file", default=None, type=click.Path(exists=True),
              help="Read hostnames from a file (one per line).")
@click.option("--format", "fmt", type=click.Choice(["json", "csv", "html"]), default="html", show_default=True)
@click.option("-o", "--output", required=True, help="Output file path.")
@click.option("-p", "--port", default=443, show_default=True)
@click.option("-t", "--timeout", default=10, show_default=True)
def report(hostnames, file, fmt, output, port, timeout):
    """
    Generate a report for one or more domains and save to OUTPUT.

    Pass hostnames directly as arguments, or use --file to read from a file.

    \b
    Examples:
      certchecker report google.com github.com -o report.html
      certchecker report google.com --format csv -o report.csv
      certchecker report --file domains.txt --format json -o report.json
    """
    console.print(BANNER)

    try:
        hostname_list = _resolve_hostnames(hostnames, file)
    except click.UsageError as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        sys.exit(1)

    if not hostname_list:
        console.print("[red]No valid hostnames found.[/red]")
        sys.exit(1)

    results = []
    progress = make_progress()
    with progress:
        task = progress.add_task("Checking domains…", total=len(hostname_list))
        for hostname in hostname_list:
            progress.update(task, description=f"[cyan]{hostname}…")
            try:
                result = get_certificate(hostname, port=port, timeout=timeout)
            except CertCheckError as e:
                result = {"hostname": hostname, "port": port, "error": str(e),
                          "is_valid": False, "is_expired": False, "days_remaining": 0,
                          "subject": {}, "issuer": {}, "weaknesses": [str(e)]}
            results.append(result)
            progress.advance(task)

    if fmt == "json":
        export_json(results, output_path=output)
    elif fmt == "csv":
        export_csv(results, output_path=output)
    elif fmt == "html":
        export_html(results, output_path=output)

    console.print(f"\n[bold green]✅ Report saved:[/bold green] {output}")
    console.print(f"[dim]Format: {fmt.upper()}  |  Domains: {len(hostname_list)}[/dim]")


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _render_http_panel(http_result: dict) -> None:
    """Render the HTTP security checks panel."""
    # Redirect / HSTS
    http_tbl = Table(title="🌐 HTTP Security", box=box.ROUNDED, title_style="bold green", border_style="green")
    http_tbl.add_column("Check", style="bold cyan")
    http_tbl.add_column("Result")

    redirects = http_result.get("http_redirects_to_https")
    http_tbl.add_row(
        "HTTP → HTTPS Redirect",
        Text("YES ✅", style="green") if redirects else (
            Text("NO ❌", style="red") if redirects is False else Text("N/A", style="dim")
        ),
    )

    hsts = http_result.get("hsts_enabled", False)
    hsts_str = "Disabled ❌"
    if hsts:
        max_age = http_result.get("hsts_max_age", 0)
        subs = " includeSubdomains" if http_result.get("hsts_include_subdomains") else ""
        pre = " preload" if http_result.get("hsts_preload") else ""
        hsts_str = f"✅ max-age={max_age}{subs}{pre}"
    http_tbl.add_row("HSTS", Text(hsts_str, style="green" if hsts else "red"))

    status = http_result.get("status_code")
    if status:
        http_tbl.add_row("HTTPS Status", str(status))
    srv = http_result.get("server")
    if srv:
        http_tbl.add_row("Server", srv)

    redirect_chain = http_result.get("redirect_chain", [])
    if redirect_chain:
        http_tbl.add_row("Redirect Chain", " → ".join(redirect_chain[:4]))

    console.print(http_tbl)
    console.print()

    # Security headers
    present = http_result.get("present_headers", [])
    missing = http_result.get("missing_headers", [])

    hdr_tbl = Table(
        title="🛡  Security Headers",
        box=box.ROUNDED,
        title_style="bold yellow",
        border_style="yellow",
        show_lines=False,
    )
    hdr_tbl.add_column("Header", style="bold cyan")
    hdr_tbl.add_column("Status", justify="center")
    hdr_tbl.add_column("Value / Description")

    for h in present:
        val = h["value"]
        if len(val) > 60:
            val = val[:57] + "…"
        hdr_tbl.add_row(h["header"], Text("✅", style="green"), val)

    for h in missing:
        hdr_tbl.add_row(h["header"], Text("❌", style="red"), Text(h["description"], style="dim"))

    console.print(hdr_tbl)
    console.print()


def _print_bulk_stats(results: list, warn_days: int, critical_days: int) -> None:
    """Print summary statistics after a bulk check."""
    total = len(results)
    valid = sum(1 for r in results if r.get("is_valid"))
    expired = sum(1 for r in results if r.get("is_expired"))
    critical = sum(1 for r in results if not r.get("is_expired") and 0 < r.get("days_remaining", 999) <= critical_days)
    warning = sum(1 for r in results if not r.get("is_expired") and r.get("days_remaining", 999) <= warn_days and r.get("days_remaining", 999) > critical_days)
    errors = sum(1 for r in results if "error" in r)

    stats_tbl = Table(box=box.SIMPLE, show_header=False)
    stats_tbl.add_column("Stat", style="bold cyan")
    stats_tbl.add_column("Count", justify="right")

    stats_tbl.add_row("Total checked", str(total))
    stats_tbl.add_row("✅ Valid", Text(str(valid), style="green"))
    stats_tbl.add_row("⚠️  Warning", Text(str(warning), style="yellow"))
    stats_tbl.add_row("🚨 Critical", Text(str(critical), style="orange1"))
    stats_tbl.add_row("💀 Expired", Text(str(expired), style="red"))
    if errors:
        stats_tbl.add_row("❌ Errors", Text(str(errors), style="bright_red"))

    console.print()
    console.print(Panel(stats_tbl, title="[bold blue]📊 Bulk Check Summary[/bold blue]", border_style="blue"))


# ─── entrypoint ───────────────────────────────────────────────────────────────

def main():
    cli()


if __name__ == "__main__":
    main()
