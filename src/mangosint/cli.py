"""Command Line Interface for mangosint"""

import asyncio
import typer
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from mangosint.core.config import Config
from mangosint.core.input import BatchScanner

app = typer.Typer(
    name="mangosint",
    help="Privacy-First Modular OSINT & Infrastructure Intelligence Framework",
    add_completion=False,
)

console = Console()


def _handle_first_run() -> bool:
    """Handle first-run safety prompt"""
    from rich.prompt import Prompt, Confirm
    from rich.panel import Panel

    console.print()
    console.print(Panel.fit(
        "[bold red]⚠ mangosint Network Safety ⚠[/bold red]\n\n"
        "External connections require a proxy.\n\n"
        "[1] Fetch & validate free proxies from GitHub\n"
        "[2] Provide my own proxy\n"
        "[3] Use Tor\n"
        "[4] Offline mode",
        title="First Run Setup",
        border_style="red"
    ))

    choice = Prompt.ask("Choose an option", choices=["1", "2", "3", "4"], default="1")

    config = Config()

    if choice == "1":
        console.print("[green]Fetching proxies from GitHub...[/green]")
        # TODO: Implement proxy fetching
        config.network.mode = "passive"
        config.proxy.type = "socks5"
        config.proxy.host = "127.0.0.1"  # Placeholder
        config.proxy.port = 1080
        config.proxy_pool.enabled = True
        config.proxy_pool.sources = ["github:proxifly"]

    elif choice == "2":
        proxy_url = Prompt.ask("Enter proxy URL (e.g., socks5://host:port)")
        # Parse proxy URL
        if "://" in proxy_url:
            protocol, rest = proxy_url.split("://", 1)
            if ":" in rest:
                host, port_str = rest.rsplit(":", 1)
                try:
                    port = int(port_str)
                    config.network.mode = "passive"
                    config.proxy.type = protocol
                    config.proxy.host = host
                    config.proxy.port = port
                except ValueError:
                    console.print("[red]Invalid proxy format[/red]")
                    return False
            else:
                console.print("[red]Invalid proxy format[/red]")
                return False
        else:
            console.print("[red]Invalid proxy format[/red]")
            return False

    elif choice == "3":
        console.print("[green]Configuring for Tor...[/green]")
        config.network.mode = "tor"
        config.proxy.type = "socks5"
        config.proxy.host = "127.0.0.1"
        config.proxy.port = 9050

    elif choice == "4":
        config.network.mode = "offline"

    config.save()
    console.print("[green]Configuration saved![/green]")
    return True


async def _show_proxy_status(config: Config):
    """Show proxy status"""
    from mangosint.core.proxy import ProxyManager

    proxy_manager = ProxyManager(config)

    if config.proxy_pool.enabled:
        console.print("[green]Proxy pool enabled[/green]")
        console.print(f"Sources: {', '.join(config.proxy_pool.sources)}")
        console.print(f"Rotation: {config.proxy_pool.rotation}")

        # Try to load proxies
        try:
            await proxy_manager.load_and_validate_proxies()
            console.print(f"Validated proxies: {len(proxy_manager.validated_proxies)}")
        except Exception as e:
            console.print(f"[red]Error loading proxies: {e}[/red]")
    else:
        console.print("[yellow]Proxy pool disabled[/yellow]")

    current_proxy = proxy_manager.get_current_proxy()
    if current_proxy:
        console.print(f"Current proxy: {current_proxy.to_url()}")
    else:
        console.print("[yellow]No current proxy configured[/yellow]")


async def _show_module_status(config: Config):
    """Show module status"""
    from mangosint.core.scanner import Scanner

    scanner = Scanner(config)
    await scanner.initialize()

    console.print(f"Loaded modules: {len(scanner.modules)}")
    for module in scanner.modules:
        status = "[green]✓[/green]" if hasattr(module, 'network_client') else "[yellow]⚠[/yellow]"
        console.print(f"  {status} {module.name}: {module.description}")


def main():
    """Main entry point"""
    asyncio.run(app())


@app.callback()
def callback():
    """mangosint - Privacy-First Modular OSINT & Infrastructure Intelligence Framework"""
    pass


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target to scan (domain, IP, URL, ASN, etc.)"),
    deep: bool = typer.Option(False, "--deep", help="Perform deep scanning"),
    passive_only: bool = typer.Option(False, "--passive-only", help="Use passive sources only"),
    active: bool = typer.Option(False, "--active", help="Enable active probing"),
    network: str = typer.Option("passive", "--network", help="Network mode (offline, passive, active, tor, custom)"),
    threads: int = typer.Option(10, "--threads", help="Number of threads"),
    enable: str = typer.Option(None, "--enable", help="Comma-separated list of sources to enable"),
    disable: str = typer.Option(None, "--disable", help="Comma-separated list of sources to disable"),
    output: str = typer.Option("json", "--output", help="Output format (json, txt, csv, sqlite, html)"),
    export: str = typer.Option(None, "--export", help="Export format (graphml, neo4j, mermaid)"),
    config_file: str = typer.Option(None, "--config", help="Path to config file"),
):
    """Scan a target for intelligence"""
    import asyncio
    asyncio.run(_scan_async(target, deep, passive_only, active, network, threads, enable, disable, output, export, config_file))


async def _scan_async(target, deep, passive_only, active, network, threads, enable, disable, output, export, config_file):
    try:
        # Load configuration
        config = Config.load(config_file)

        # Check if first run or proxy not configured
        if not config or not config.proxy.host or config.network.mode == "offline":
            if not _handle_first_run():
                console.print("[red]Proxy setup required for network operations. Use 'mangosint init' or configure manually.[/red]")
                raise typer.Exit(1)
            config = Config.load(config_file)  # Reload after setup

        # Override config with CLI options
        if network:
            config.network.mode = network
        if threads:
            config.threads = threads

        # Parse source options
        enabled_sources = enable.split(",") if enable else None
        disabled_sources = disable.split(",") if disable else None

        # Create batch scanner
        batch_scanner = BatchScanner(config)
        await batch_scanner.initialize()

        # Process input
        input_normalizer = batch_scanner.input_normalizer
        targets = await input_normalizer.process_input(target)

        # Perform scan
        console.print(f"[bold green]Scanning {len(targets)} target(s)[/bold green]")
        results = await batch_scanner.scan_batch(targets, deep=deep, passive_only=passive_only, active=active,
                                                enabled_sources=enabled_sources, disabled_sources=disabled_sources)

        # Output results
        if len(results) == 1:
            batch_scanner.scanner.output_results(results[0], output_format=output, export_format=export)
        else:
            # For multiple results, output as array
            import json
            print(json.dumps(results, indent=2))

        console.print("[bold green]Scan completed successfully![/bold green]")

    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(1)


@app.command()
def status(
    component: str = typer.Argument(..., help="Component to check status (network, proxies, modules)"),
):
    """Check status of various components"""
    import asyncio
    asyncio.run(_status_async(component))


async def _status_async(component: str):
    config = Config.load()

    if component == "network":
        console.print(Panel.fit(
            f"Network Mode: {config.network.mode}\n"
            f"Force Proxy: {config.network.force_proxy}\n"
            f"DNS over Proxy: {config.network.dns_over_proxy}\n"
            f"IPv6 Disabled: {not config.network.ipv6}",
            title="Network Status"
        ))
    elif component == "proxies":
        await _show_proxy_status(config)
    elif component == "modules":
        await _show_module_status(config)
    else:
        console.print(f"[red]Unknown component: {component}[/red]")
        raise typer.Exit(1)


@app.command()
def list_sources():
    """List available sources"""
    import asyncio
    asyncio.run(_list_sources_async())


async def _list_sources_async():
    from mangosint.core.scanner import Scanner

    config = Config.load()
    scanner = Scanner(config)
    await scanner.initialize()

    console.print("[bold]Available Sources:[/bold]")
    for module in scanner.modules:
        console.print(f"  • {module.name}: {module.description}")
        console.print(f"    Permissions: {', '.join(module.permissions)}")
        console.print()


@app.command()
def init():
    """Initialize mangosint configuration"""
    config = Config()
    config.save()

    console.print("[green]Configuration initialized![/green]")
    console.print("Edit config.json to customize settings.")


if __name__ == "__main__":
    main()