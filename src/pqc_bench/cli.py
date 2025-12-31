"""
Command-line interface for PQC-Bench.

Provides natural language recommendations, algorithm details,
comparisons, and migration guidance.
"""

from typing import Optional

import typer
from rich.console import Console

from . import __version__
from .core.constraints import Constraints
from .core.engine import RecommendationEngine
from .core.parser import QueryParser
from .data.algorithms import get_algorithm, get_algorithms_by_type, ALGORITHMS
from .data.compliance import COMPLIANCE_FRAMEWORKS, get_framework
from .output.terminal import TerminalOutput
from .output.json import JsonOutput

app = typer.Typer(
    name="pqc-bench",
    help="Post-Quantum Cryptography Benchmarking and Recommendation Engine",
    no_args_is_help=True,
    add_completion=False,
)

console = Console()
terminal = TerminalOutput(console)


def version_callback(value: bool) -> None:
    """Print version and exit."""
    if value:
        console.print(f"pqc-bench {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-v",
        callback=version_callback,
        is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    """
    PQC-Bench: Post-Quantum Cryptography Recommendations

    Get algorithm recommendations by describing your use case:

        pqc-bench recommend "REST API with JWT auth on AWS Lambda"

    Or explore specific algorithms:

        pqc-bench explain ml-dsa-65
    """
    pass


@app.command()
def recommend(
    query: str = typer.Argument(
        ...,
        help="Describe your use case in natural language",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Show detailed output with scoring factors",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        "-j",
        help="Output as JSON for CI/CD integration",
    ),
    top_n: int = typer.Option(
        3,
        "--top",
        "-n",
        help="Number of recommendations to show",
    ),
) -> None:
    """
    Get algorithm recommendations for your use case.

    Describe your requirements in natural language and receive
    tailored recommendations with explanations.

    Examples:

        pqc-bench recommend "JWT auth for mobile app"

        pqc-bench recommend "TLS for government web server" --verbose

        pqc-bench recommend "file encryption for healthcare" --json
    """
    parser = QueryParser()
    engine = RecommendationEngine()

    # Parse query into constraints
    constraints = parser.parse(query)

    # Generate recommendations
    result = engine.recommend(constraints, query=query, top_n=top_n)

    # Output
    if json_output:
        json_formatter = JsonOutput()
        console.print(json_formatter.format(result))
    else:
        terminal.print_recommendation(result, verbose=verbose)


@app.command()
def explain(
    algorithm: str = typer.Argument(
        ...,
        help="Algorithm ID (e.g., ml-dsa-65, ml-kem-768)",
    ),
) -> None:
    """
    Show detailed information about a specific algorithm.

    Examples:

        pqc-bench explain ml-dsa-65

        pqc-bench explain ml-kem-768

        pqc-bench explain falcon-512
    """
    algo = get_algorithm(algorithm)

    if algo is None:
        console.print(f"[red]Unknown algorithm: {algorithm}[/red]")
        console.print()
        console.print("Available algorithms:")
        for algo_id in sorted(ALGORITHMS.keys()):
            console.print(f"  • {algo_id}")
        raise typer.Exit(1)

    terminal.print_algorithm_details(algo)


@app.command()
def compare(
    algorithm1: str = typer.Argument(..., help="First algorithm ID"),
    algorithm2: str = typer.Argument(..., help="Second algorithm ID"),
) -> None:
    """
    Compare two algorithms side-by-side.

    Examples:

        pqc-bench compare ml-dsa-44 ml-dsa-65

        pqc-bench compare ml-dsa-44 falcon-512
    """
    algo1 = get_algorithm(algorithm1)
    algo2 = get_algorithm(algorithm2)

    if algo1 is None:
        console.print(f"[red]Unknown algorithm: {algorithm1}[/red]")
        raise typer.Exit(1)

    if algo2 is None:
        console.print(f"[red]Unknown algorithm: {algorithm2}[/red]")
        raise typer.Exit(1)

    console.print()
    console.print(f"[bold]Comparison: {algo1.names.nist_name} vs {algo2.names.nist_name}[/bold]")
    console.print("═" * 60)
    console.print()

    # Create comparison table
    from rich.table import Table
    from rich import box

    table = Table(box=box.ROUNDED, show_header=True, header_style="bold")
    table.add_column("Property", style="dim")
    table.add_column(algo1.names.nist_name)
    table.add_column(algo2.names.nist_name)
    table.add_column("Winner", justify="center")

    # Security Level
    winner = "=" if algo1.security.nist_level == algo2.security.nist_level else (
        algo1.names.nist_name if algo1.security.nist_level > algo2.security.nist_level
        else algo2.names.nist_name
    )
    table.add_row(
        "Security Level",
        f"Level {algo1.security.nist_level}",
        f"Level {algo2.security.nist_level}",
        winner if winner != "=" else "[dim]tie[/dim]",
    )

    # Public Key Size
    winner = "=" if algo1.sizes.public_key == algo2.sizes.public_key else (
        algo1.names.nist_name if algo1.sizes.public_key < algo2.sizes.public_key
        else algo2.names.nist_name
    )
    table.add_row(
        "Public Key",
        f"{algo1.sizes.public_key:,} bytes",
        f"{algo2.sizes.public_key:,} bytes",
        winner if winner != "=" else "[dim]tie[/dim]",
    )

    # Signature/Ciphertext Size
    if algo1.is_signature and algo2.is_signature:
        s1 = algo1.sizes.signature or 0
        s2 = algo2.sizes.signature or 0
        winner = "=" if s1 == s2 else (
            algo1.names.nist_name if s1 < s2 else algo2.names.nist_name
        )
        table.add_row(
            "Signature",
            f"{s1:,} bytes",
            f"{s2:,} bytes",
            winner if winner != "=" else "[dim]tie[/dim]",
        )
    elif algo1.is_kem and algo2.is_kem:
        c1 = algo1.sizes.ciphertext or 0
        c2 = algo2.sizes.ciphertext or 0
        winner = "=" if c1 == c2 else (
            algo1.names.nist_name if c1 < c2 else algo2.names.nist_name
        )
        table.add_row(
            "Ciphertext",
            f"{c1:,} bytes",
            f"{c2:,} bytes",
            winner if winner != "=" else "[dim]tie[/dim]",
        )

    # Constant-time
    ct1 = "[green]Yes[/green]" if algo1.security.constant_time else "[yellow]No[/yellow]"
    ct2 = "[green]Yes[/green]" if algo2.security.constant_time else "[yellow]No[/yellow]"
    winner = "=" if algo1.security.constant_time == algo2.security.constant_time else (
        algo1.names.nist_name if algo1.security.constant_time else algo2.names.nist_name
    )
    table.add_row(
        "Constant-time",
        ct1,
        ct2,
        winner if winner != "=" else "[dim]tie[/dim]",
    )

    # NIST Standardized
    std1 = "[green]Yes[/green]" if algo1.compliance.nist_standardized else "[yellow]No[/yellow]"
    std2 = "[green]Yes[/green]" if algo2.compliance.nist_standardized else "[yellow]No[/yellow]"
    winner = "=" if algo1.compliance.nist_standardized == algo2.compliance.nist_standardized else (
        algo1.names.nist_name if algo1.compliance.nist_standardized else algo2.names.nist_name
    )
    table.add_row(
        "NIST Standard",
        std1,
        std2,
        winner if winner != "=" else "[dim]tie[/dim]",
    )

    # FPU Required
    fpu1 = "[yellow]Yes[/yellow]" if algo1.requirements.requires_fpu else "[green]No[/green]"
    fpu2 = "[yellow]Yes[/yellow]" if algo2.requirements.requires_fpu else "[green]No[/green]"
    winner = "=" if algo1.requirements.requires_fpu == algo2.requirements.requires_fpu else (
        algo1.names.nist_name if not algo1.requirements.requires_fpu else algo2.names.nist_name
    )
    table.add_row(
        "Requires FPU",
        fpu1,
        fpu2,
        winner if winner != "=" else "[dim]tie[/dim]",
    )

    console.print(table)
    console.print()


@app.command()
def migrate(
    from_algo: str = typer.Option(
        ...,
        "--from",
        "-f",
        help="Classical algorithm to migrate from (e.g., rsa-2048, ecdsa-p256)",
    ),
) -> None:
    """
    Get migration guidance from a classical algorithm.

    Examples:

        pqc-bench migrate --from rsa-2048

        pqc-bench migrate --from ecdsa-p256

        pqc-bench migrate --from ecdh-p256
    """
    from_lower = from_algo.lower().replace("-", "").replace("_", "")

    # Define classical algorithm properties and PQC recommendations
    migrations = {
        "rsa2048": {
            "name": "RSA-2048",
            "type": "signature",
            "pub_key": 294,
            "signature": 256,
            "recommendation": "ml-dsa-65",
            "alternative": "ml-dsa-44",
        },
        "rsa4096": {
            "name": "RSA-4096",
            "type": "signature",
            "pub_key": 550,
            "signature": 512,
            "recommendation": "ml-dsa-87",
            "alternative": "ml-dsa-65",
        },
        "ecdsap256": {
            "name": "ECDSA P-256",
            "type": "signature",
            "pub_key": 64,
            "signature": 64,
            "recommendation": "ml-dsa-44",
            "alternative": "falcon-512",
        },
        "ecdsap384": {
            "name": "ECDSA P-384",
            "type": "signature",
            "pub_key": 96,
            "signature": 96,
            "recommendation": "ml-dsa-65",
            "alternative": "ml-dsa-44",
        },
        "ed25519": {
            "name": "Ed25519",
            "type": "signature",
            "pub_key": 32,
            "signature": 64,
            "recommendation": "ml-dsa-44",
            "alternative": "falcon-512",
        },
        "ecdhp256": {
            "name": "ECDH P-256",
            "type": "kem",
            "pub_key": 64,
            "ciphertext": 64,
            "recommendation": "ml-kem-768",
            "alternative": "ml-kem-512",
        },
        "x25519": {
            "name": "X25519",
            "type": "kem",
            "pub_key": 32,
            "ciphertext": 32,
            "recommendation": "ml-kem-768",
            "alternative": "ml-kem-512",
        },
    }

    if from_lower not in migrations:
        console.print(f"[red]Unknown classical algorithm: {from_algo}[/red]")
        console.print()
        console.print("Supported classical algorithms:")
        for key, val in migrations.items():
            console.print(f"  • {val['name']}")
        raise typer.Exit(1)

    classical = migrations[from_lower]
    pqc_algo = get_algorithm(classical["recommendation"])
    alt_algo = get_algorithm(classical["alternative"])

    if pqc_algo is None:
        console.print("[red]Internal error: recommended algorithm not found[/red]")
        raise typer.Exit(1)

    console.print()
    console.print(f"[bold]Migration: {classical['name']} → {pqc_algo.names.nist_name}[/bold]")
    console.print("═" * 60)
    console.print()

    # Size comparison
    from rich.table import Table
    from rich import box

    table = Table(box=box.ROUNDED, show_header=True, header_style="bold")
    table.add_column("Property", style="dim")
    table.add_column(classical["name"])
    table.add_column(pqc_algo.names.nist_name)
    table.add_column("Change")

    # Public key
    classical_pk = classical["pub_key"]
    pqc_pk = pqc_algo.sizes.public_key
    change = f"+{pqc_pk - classical_pk:,} bytes (+{((pqc_pk/classical_pk)-1)*100:.0f}%)"
    table.add_row("Public Key", f"{classical_pk} bytes", f"{pqc_pk:,} bytes", change)

    # Signature or ciphertext
    if classical["type"] == "signature":
        classical_sig = classical["signature"]
        pqc_sig = pqc_algo.sizes.signature or 0
        change = f"+{pqc_sig - classical_sig:,} bytes (+{((pqc_sig/classical_sig)-1)*100:.0f}%)"
        table.add_row("Signature", f"{classical_sig} bytes", f"{pqc_sig:,} bytes", change)
    else:
        classical_ct = classical["ciphertext"]
        pqc_ct = pqc_algo.sizes.ciphertext or 0
        change = f"+{pqc_ct - classical_ct:,} bytes (+{((pqc_ct/classical_ct)-1)*100:.0f}%)"
        table.add_row("Ciphertext", f"{classical_ct} bytes", f"{pqc_ct:,} bytes", change)

    console.print(table)
    console.print()

    # Impact analysis
    console.print("[bold]Impact Analysis[/bold]")
    console.print("─" * 40)

    if classical["type"] == "signature":
        console.print(f"  • JWT tokens will grow by ~{(pqc_algo.sizes.signature or 0) - classical['signature']:,} bytes")
        console.print(f"  • Certificate chains will be significantly larger")
        console.print(f"  • Signing/verification performance similar or better")
    else:
        console.print(f"  • TLS handshake will transfer ~{(pqc_algo.sizes.ciphertext or 0) - classical['ciphertext']:,} more bytes")
        console.print(f"  • Key exchange performance similar or better")

    console.print()

    # Alternative
    if alt_algo:
        console.print("[bold]Alternative[/bold]")
        console.print("─" * 40)
        console.print(f"  {alt_algo.names.nist_name}: ", end="")
        if alt_algo.id == "falcon-512":
            console.print("Smaller signatures (666 bytes) but requires FPU, not constant-time")
        elif "512" in alt_algo.id:
            console.print("Smaller/faster but lower security level (Level 1)")
        else:
            console.print(f"Security Level {alt_algo.security.nist_level}")

    console.print()

    # Recommendation
    console.print("[bold]Recommendation[/bold]")
    console.print("─" * 40)
    console.print(f"  Use [green]{pqc_algo.names.nist_name}[/green] for most applications.")
    console.print()
    console.print(f"  Run [cyan]pqc-bench explain {pqc_algo.id}[/cyan] for full details.")
    console.print()


@app.command()
def compliance(
    framework: str = typer.Argument(
        ...,
        help="Compliance framework (e.g., cnsa-2.0, fips-140-3, pci-dss)",
    ),
    use_case: Optional[str] = typer.Option(
        None,
        "--use-case",
        "-u",
        help="Filter by use case (e.g., tls, jwt, file-encryption)",
    ),
) -> None:
    """
    Show compliance framework requirements for PQC.

    Examples:

        pqc-bench compliance cnsa-2.0

        pqc-bench compliance fips-140-3 --use-case tls

        pqc-bench compliance pci-dss
    """
    fw = get_framework(framework)

    if fw is None:
        console.print(f"[red]Unknown compliance framework: {framework}[/red]")
        console.print()
        console.print("Supported frameworks:")
        for fw_id, fw_data in COMPLIANCE_FRAMEWORKS.items():
            console.print(f"  • {fw_id}: {fw_data.name}")
        raise typer.Exit(1)

    console.print()
    console.print(f"[bold]{fw.name}[/bold]")
    console.print("═" * 60)
    console.print()

    console.print(f"[dim]Authority:[/dim] {fw.authority}")
    console.print(f"[dim]URL:[/dim] [cyan]{fw.url}[/cyan]")
    console.print()

    console.print("[bold]Description[/bold]")
    console.print("─" * 40)
    console.print(f"  {fw.description}")
    console.print()

    console.print("[bold]Algorithm Requirements[/bold]")
    console.print("─" * 40)

    if fw.requirements.kem_algorithms:
        console.print("  [dim]Key Encapsulation (KEM):[/dim]")
        for algo_id in fw.requirements.kem_algorithms:
            algo = get_algorithm(algo_id)
            if algo:
                console.print(f"    • {algo.names.nist_name}")
            else:
                console.print(f"    • {algo_id}")

    if fw.requirements.signature_algorithms:
        console.print("  [dim]Digital Signatures:[/dim]")
        for algo_id in fw.requirements.signature_algorithms:
            algo = get_algorithm(algo_id)
            if algo:
                console.print(f"    • {algo.names.nist_name}")
            else:
                console.print(f"    • {algo_id}")

    console.print(f"  [dim]Minimum Security Level:[/dim] NIST Level {fw.requirements.min_security_level}")

    if fw.requirements.notes:
        console.print(f"  [dim]Notes:[/dim] {fw.requirements.notes}")

    console.print()

    if fw.timeline:
        console.print("[bold]Timeline[/bold]")
        console.print("─" * 40)
        if fw.timeline.prefer_by:
            console.print(f"  • Prefer PQC by: {fw.timeline.prefer_by}")
        if fw.timeline.require_by:
            console.print(f"  • Require PQC by: {fw.timeline.require_by}")
        if fw.timeline.exclusive_by:
            console.print(f"  • Exclusive PQC by: {fw.timeline.exclusive_by}")
        if fw.timeline.notes:
            console.print(f"  [dim]{fw.timeline.notes}[/dim]")
        console.print()

    if fw.applies_to:
        console.print("[bold]Applies To[/bold]")
        console.print("─" * 40)
        for applies in fw.applies_to:
            console.print(f"  • {applies}")
        console.print()

    if fw.citations:
        console.print("[bold]References[/bold]")
        console.print("─" * 40)
        for citation in fw.citations:
            console.print(f"  [cyan]{citation}[/cyan]")
        console.print()


@app.command("list")
def list_algorithms(
    algorithm_type: Optional[str] = typer.Option(
        None,
        "--type",
        "-t",
        help="Filter by type: kem or signature",
    ),
) -> None:
    """
    List all available algorithms.

    Examples:

        pqc-bench list

        pqc-bench list --type signature

        pqc-bench list --type kem
    """
    console.print()
    console.print("[bold]Available Algorithms[/bold]")
    console.print("═" * 60)
    console.print()

    from rich.table import Table
    from rich import box

    table = Table(box=box.SIMPLE, show_header=True, header_style="bold")
    table.add_column("ID")
    table.add_column("Name")
    table.add_column("Type")
    table.add_column("Level")
    table.add_column("NIST")

    for algo_id, algo in sorted(ALGORITHMS.items()):
        if algorithm_type:
            if algorithm_type.lower() not in [algo.algorithm_type, algo.algorithm_type + "s"]:
                continue

        nist = "[green]Yes[/green]" if algo.compliance.nist_standardized else "[yellow]Pending[/yellow]"
        table.add_row(
            algo_id,
            algo.names.nist_name,
            algo.algorithm_type.upper(),
            str(algo.security.nist_level),
            nist,
        )

    console.print(table)
    console.print()


if __name__ == "__main__":
    app()
