"""
Command-line interface for PQC-Bench.

Provides natural language recommendations, algorithm details,
comparisons, and migration guidance.
"""


import typer
from rich.console import Console

from . import __version__
from .core.engine import RecommendationEngine
from .core.parser import QueryParser
from .data.algorithms import ALGORITHMS, get_algorithm
from .data.compliance import COMPLIANCE_FRAMEWORKS, get_framework
from .data.libraries import (
    HYBRID_MODES,
    LIBRARIES,
    ProductionReadiness,
    get_libraries_for_algorithm,
    get_libraries_with_fips,
    get_production_ready_libraries,
)
from .data.protocol_impact import (
    analyze_certificate_chain,
    calculate_tls_kem_impact,
    calculate_tls_signature_impact,
    get_ossification_risks,
)
from .data.threat_model import (
    DATA_PROFILES,
    ThreatUrgency,
    assess_sndl_risk,
    get_profiles_by_urgency,
)
from .output.json import JsonOutput
from .output.terminal import TerminalOutput

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
    version: bool | None = typer.Option(
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
    from rich import box
    from rich.table import Table

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
        for _key, val in migrations.items():
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
    from rich import box
    from rich.table import Table

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
        sig_diff = (pqc_algo.sizes.signature or 0) - classical["signature"]
        console.print(f"  • JWT tokens will grow by ~{sig_diff:,} bytes")
        console.print("  • Certificate chains will be significantly larger")
        console.print("  • Signing/verification performance similar or better")
    else:
        ct_diff = (pqc_algo.sizes.ciphertext or 0) - classical["ciphertext"]
        console.print(f"  • TLS handshake will transfer ~{ct_diff:,} more bytes")
        console.print("  • Key exchange performance similar or better")

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
    use_case: str | None = typer.Option(
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
    algorithm_type: str | None = typer.Option(
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

    from rich import box
    from rich.table import Table

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


@app.command()
def libraries(
    production_only: bool = typer.Option(
        False,
        "--production",
        "-p",
        help="Show only production-ready libraries",
    ),
    fips_only: bool = typer.Option(
        False,
        "--fips",
        "-f",
        help="Show only FIPS-validated libraries",
    ),
    algorithm: str | None = typer.Option(
        None,
        "--algorithm",
        "-a",
        help="Show libraries supporting a specific algorithm",
    ),
) -> None:
    """
    List cryptographic libraries with production-readiness ratings.

    This is critical information - liboqs is explicitly NOT production-ready,
    yet many developers use it unaware of this.

    Examples:

        pqc-bench libraries

        pqc-bench libraries --production

        pqc-bench libraries --fips

        pqc-bench libraries --algorithm ml-kem-768
    """
    from rich import box
    from rich.table import Table

    console.print()
    console.print("[bold]Cryptographic Libraries for PQC[/bold]")
    console.print("═" * 70)
    console.print()

    # Filter libraries
    if fips_only:
        libs = get_libraries_with_fips()
    elif production_only:
        libs = get_production_ready_libraries()
    elif algorithm:
        libs = get_libraries_for_algorithm(algorithm)
        if not libs:
            console.print(f"[yellow]No libraries found supporting {algorithm}[/yellow]")
            console.print()
            return
    else:
        libs = list(LIBRARIES.values())

    table = Table(box=box.ROUNDED, show_header=True, header_style="bold")
    table.add_column("Library")
    table.add_column("Production")
    table.add_column("FIPS")
    table.add_column("Notable Users")

    for lib in libs:
        # Production readiness styling
        if lib.production_readiness == ProductionReadiness.PRODUCTION:
            prod = "[green]Production[/green]"
        elif lib.production_readiness == ProductionReadiness.EXPERIMENTAL:
            prod = "[red]Experimental[/red]"
        elif lib.production_readiness == ProductionReadiness.TRANSITIONAL:
            prod = "[yellow]Transitional[/yellow]"
        else:
            prod = "[dim]Deprecated[/dim]"

        # FIPS styling
        if lib.fips_cert_number:
            fips = f"[green]#{lib.fips_cert_number}[/green]"
        else:
            fips = "[dim]No[/dim]"

        # Notable users
        users = ", ".join(lib.notable_users[:3]) if lib.notable_users else "-"

        table.add_row(lib.name, prod, fips, users)

    console.print(table)
    console.print()

    # Show critical warning about liboqs
    liboqs = LIBRARIES.get("liboqs")
    if liboqs and not production_only and not fips_only:
        console.print("[bold red]CRITICAL WARNING[/bold red]")
        console.print("─" * 40)
        console.print("  liboqs is explicitly NOT production-ready.")
        console.print("  Per liboqs README: 'NOT safe for production'")
        console.print()
        console.print("  For production, use: AWS-LC, BoringSSL, or OpenSSL 3.5+")
        console.print()


@app.command()
def hybrid(
    use_case: str | None = typer.Option(
        None,
        "--use-case",
        "-u",
        help="Filter by use case (tls, certificate)",
    ),
) -> None:
    """
    Show hybrid cryptography modes (classical + PQC).

    Hybrid modes are the practical migration path - they provide
    security if either the classical OR PQC algorithm is secure.

    Examples:

        pqc-bench hybrid

        pqc-bench hybrid --use-case tls
    """

    console.print()
    console.print("[bold]Hybrid Cryptography Modes[/bold]")
    console.print("═" * 70)
    console.print()

    console.print("[dim]Hybrid modes combine classical + PQC for defense-in-depth:[/dim]")
    console.print("[dim]If either algorithm is secure, the combination is secure.[/dim]")
    console.print()

    # Filter modes
    if use_case:
        from .data.libraries import get_hybrid_modes_for_use_case
        modes = get_hybrid_modes_for_use_case(use_case)
    else:
        modes = list(HYBRID_MODES.values())

    for mode in modes:
        console.print(f"[bold cyan]{mode.name}[/bold cyan]")
        console.print("─" * 50)
        console.print(f"  {mode.description}")
        console.print()
        console.print(f"  [dim]Classical:[/dim] {mode.classical_algorithm}")
        console.print(f"  [dim]PQC:[/dim] {mode.pqc_algorithm}")
        console.print(f"  [dim]Combined size:[/dim] {mode.combined_size:,} bytes")
        console.print()

        # Support matrix
        supports = []
        if mode.chrome_support:
            supports.append("[green]Chrome[/green]")
        if mode.cloudflare_support:
            supports.append("[green]Cloudflare[/green]")
        if mode.tls_support:
            supports.append("[green]TLS[/green]")

        if supports:
            console.print(f"  [dim]Browser/CDN support:[/dim] {', '.join(supports)}")
        else:
            console.print("  [dim]Browser/CDN support:[/dim] [yellow]Not yet[/yellow]")

        if mode.ietf_draft:
            console.print(f"  [dim]IETF Draft:[/dim] {mode.ietf_draft}")

        console.print(f"  [dim]Recommended until:[/dim] {mode.recommended_until}")

        if mode.libraries:
            libs = [LIBRARIES.get(lib_id, type("", (), {"name": lib_id})).name for lib_id in mode.libraries]
            console.print(f"  [dim]Libraries:[/dim] {', '.join(libs)}")

        console.print()

    console.print("[bold]Why Hybrid?[/bold]")
    console.print("─" * 40)
    console.print("  1. PQC algorithms are newer; hybrid provides insurance")
    console.print("  2. X25519Kyber768 is already deployed in Chrome/Cloudflare")
    console.print("  3. NIST and NSA recommend hybrid during transition period")
    console.print()


@app.command()
def threat(
    data_type: str | None = typer.Option(
        None,
        "--data-type",
        "-d",
        help="Data type to assess (e.g., healthcare_records, intellectual_property)",
    ),
    list_types: bool = typer.Option(
        False,
        "--list",
        "-l",
        help="List all data type profiles",
    ),
    urgency: str | None = typer.Option(
        None,
        "--urgency",
        "-u",
        help="Filter by urgency level (critical, high, medium, low)",
    ),
) -> None:
    """
    Assess 'Store Now, Decrypt Later' (SNDL) threat for your data.

    The SNDL threat is the primary driver for PQC adoption: adversaries
    can capture encrypted traffic today and decrypt it when quantum
    computers become available.

    Examples:

        pqc-bench threat --list

        pqc-bench threat --data-type healthcare_records

        pqc-bench threat --urgency critical
    """
    from rich import box
    from rich.table import Table

    console.print()
    console.print("[bold]SNDL Threat Assessment[/bold]")
    console.print("═" * 70)
    console.print()

    if list_types or (not data_type and not urgency):
        # List all data profiles
        console.print("[dim]Data must be protected for: lifespan + migration time > quantum threat[/dim]")
        console.print()

        table = Table(box=box.ROUNDED, show_header=True, header_style="bold")
        table.add_column("Profile")
        table.add_column("Lifespan")
        table.add_column("Urgency")
        table.add_column("Deadline")

        for profile in DATA_PROFILES.values():
            # Urgency styling
            urgency_styles = {
                ThreatUrgency.CRITICAL: "[red]CRITICAL[/red]",
                ThreatUrgency.HIGH: "[yellow]HIGH[/yellow]",
                ThreatUrgency.MEDIUM: "[blue]MEDIUM[/blue]",
                ThreatUrgency.LOW: "[green]LOW[/green]",
                ThreatUrgency.MONITORING: "[dim]MONITOR[/dim]",
            }
            urg_str = urgency_styles.get(profile.urgency, str(profile.urgency))

            # Calculate deadline
            from .data.threat_model import calculate_migration_deadline
            deadline = calculate_migration_deadline(profile.typical_lifespan_years)
            if deadline < 0:
                deadline_str = f"[red]{abs(deadline)}y OVERDUE[/red]"
            elif deadline < 3:
                deadline_str = f"[yellow]{deadline}y[/yellow]"
            else:
                deadline_str = f"{deadline}y"

            table.add_row(
                profile.name,
                f"{profile.typical_lifespan_years}y",
                urg_str,
                deadline_str,
            )

        console.print(table)
        console.print()
        console.print("[dim]Run with --data-type <profile_id> for detailed assessment[/dim]")
        console.print()
        return

    if urgency:
        # Filter by urgency
        urgency_map = {
            "critical": ThreatUrgency.CRITICAL,
            "high": ThreatUrgency.HIGH,
            "medium": ThreatUrgency.MEDIUM,
            "low": ThreatUrgency.LOW,
            "monitoring": ThreatUrgency.MONITORING,
        }
        urg = urgency_map.get(urgency.lower())
        if not urg:
            console.print(f"[red]Unknown urgency level: {urgency}[/red]")
            console.print("Valid levels: critical, high, medium, low, monitoring")
            raise typer.Exit(1)

        profiles = get_profiles_by_urgency(urg)
        console.print(f"[bold]Data profiles with {urgency.upper()} urgency:[/bold]")
        console.print()
        for profile in profiles:
            console.print(f"  • [bold]{profile.name}[/bold]")
            console.print(f"    {profile.description}")
            console.print(f"    Action: {profile.recommended_action}")
            console.print()
        return

    # Detailed assessment for specific data type
    assessment = assess_sndl_risk(data_type)
    if not assessment:
        console.print(f"[red]Unknown data type: {data_type}[/red]")
        console.print()
        console.print("Available data types:")
        for profile_id in DATA_PROFILES.keys():
            console.print(f"  • {profile_id}")
        raise typer.Exit(1)

    profile = assessment.data_profile

    console.print(f"[bold]{profile.name}[/bold]")
    console.print("─" * 50)
    console.print()
    console.print(f"[dim]Description:[/dim] {profile.description}")
    console.print(f"[dim]Typical lifespan:[/dim] {profile.typical_lifespan_years} years")
    console.print(f"[dim]Classification:[/dim] {profile.classification.value}")
    console.print()

    # Risk assessment
    if assessment.is_at_risk:
        console.print("[bold red]⚠ AT RISK[/bold red]")
    else:
        console.print("[bold green]✓ MANAGEABLE[/bold green]")

    console.print()
    console.print(assessment.risk_explanation)
    console.print()

    console.print("[bold]Examples:[/bold]")
    for example in profile.examples:
        console.print(f"  • {example}")
    console.print()

    console.print("[bold]Recommended Action:[/bold]")
    console.print(f"  {profile.recommended_action}")
    console.print()

    if assessment.recommended_hybrid:
        console.print(f"[bold]Recommended Hybrid Mode:[/bold] {assessment.recommended_hybrid}")
    if assessment.recommended_algorithm:
        console.print(f"[bold]Recommended Algorithm:[/bold] {assessment.recommended_algorithm}")
    console.print()


@app.command()
def impact(
    algorithm: str = typer.Argument(..., help="Algorithm to analyze (e.g., ml-kem-768, ml-dsa-65)"),
    chain_length: int = typer.Option(
        3,
        "--chain-length",
        "-c",
        help="Certificate chain length for signature analysis",
    ),
) -> None:
    """
    Analyze protocol impact of using a PQC algorithm.

    Shows TLS handshake impact, certificate chain sizes,
    and potential compatibility issues.

    Examples:

        pqc-bench impact ml-kem-768

        pqc-bench impact ml-dsa-65 --chain-length 4
    """
    from rich import box
    from rich.table import Table

    algo = get_algorithm(algorithm)
    if not algo:
        console.print(f"[red]Unknown algorithm: {algorithm}[/red]")
        raise typer.Exit(1)

    console.print()
    console.print(f"[bold]Protocol Impact: {algo.names.nist_name}[/bold]")
    console.print("═" * 70)
    console.print()

    if algo.is_kem:
        impact_data = calculate_tls_kem_impact(algorithm)
        if impact_data:
            console.print("[bold]TLS 1.3 Handshake Impact (Key Exchange)[/bold]")
            console.print("─" * 50)
            console.print(f"  [dim]Baseline:[/dim] {impact_data.comparison_baseline}")
            console.print()

            table = Table(box=box.SIMPLE)
            table.add_column("Metric", style="dim")
            table.add_column("Delta")

            table.add_row("ClientHello", f"+{impact_data.client_hello_delta:,} bytes")
            table.add_row("ServerHello", f"+{impact_data.server_hello_delta:,} bytes")
            table.add_row("Total Handshake", f"+{impact_data.total_handshake_delta:,} bytes")

            console.print(table)
            console.print()

            # Fragmentation risk
            frag_colors = {"low": "green", "medium": "yellow", "high": "red"}
            frag_color = frag_colors.get(impact_data.packet_fragmentation_risk, "white")
            console.print(
                f"  [dim]Fragmentation risk:[/dim] [{frag_color}]{impact_data.packet_fragmentation_risk}[/{frag_color}]"
            )

            # Middlebox compatibility
            mb_colors = {"good": "green", "moderate": "yellow", "poor": "red"}
            mb_color = mb_colors.get(impact_data.middlebox_compatibility, "white")
            console.print(
                f"  [dim]Middlebox compatibility:[/dim] [{mb_color}]{impact_data.middlebox_compatibility}[/{mb_color}]"
            )

            if impact_data.known_issues:
                console.print()
                console.print("[bold]Known Issues:[/bold]")
                for issue in impact_data.known_issues:
                    console.print(f"  • {issue}")

    else:
        # Signature algorithm
        impact_data = calculate_tls_signature_impact(algorithm, chain_length)
        chain_data = analyze_certificate_chain(algorithm, chain_length)

        if impact_data:
            console.print(f"[bold]TLS 1.3 Handshake Impact (Certificate Chain of {chain_length})[/bold]")
            console.print("─" * 50)
            console.print(f"  [dim]Baseline:[/dim] {impact_data.comparison_baseline}")
            console.print()

            table = Table(box=box.SIMPLE)
            table.add_column("Metric", style="dim")
            table.add_column("Delta")

            table.add_row("Per Certificate", f"+{impact_data.certificate_delta:,} bytes")
            table.add_row("Total Handshake", f"+{impact_data.total_handshake_delta:,} bytes")

            console.print(table)
            console.print()

        if chain_data:
            console.print("[bold]Certificate Chain Analysis[/bold]")
            console.print("─" * 50)

            table = Table(box=box.SIMPLE)
            table.add_column("Metric", style="dim")
            table.add_column("Classical")
            table.add_column("PQC")
            table.add_column("Increase")

            table.add_row(
                "Single Cert",
                f"{chain_data.classical_cert_size:,} bytes",
                f"{chain_data.pqc_cert_size:,} bytes",
                f"{chain_data.size_increase_factor:.1f}x",
            )
            table.add_row(
                f"Chain ({chain_length})",
                f"{chain_data.classical_chain_size:,} bytes",
                f"{chain_data.pqc_chain_size:,} bytes",
                f"+{chain_data.total_increase_bytes:,} bytes",
            )
            table.add_row(
                "TCP Segments",
                str(chain_data.tcp_segments_classical),
                str(chain_data.tcp_segments_pqc),
                f"+{chain_data.additional_segments}",
            )

            console.print(table)
            console.print()

            if chain_data.mitigations:
                console.print("[bold]Mitigations:[/bold]")
                for mitigation in chain_data.mitigations:
                    console.print(f"  • {mitigation}")
                console.print()

    # Ossification risks
    risks = get_ossification_risks(algorithm)
    if risks:
        console.print("[bold]Protocol Ossification Risks[/bold]")
        console.print("─" * 50)
        for risk in risks:
            severity_colors = {"low": "green", "medium": "yellow", "high": "red"}
            sev_color = severity_colors.get(risk.severity, "white")
            console.print(f"  [{sev_color}]{risk.severity.upper()}[/{sev_color}]: {risk.description}")
            console.print(f"    [dim]Affected:[/dim] {', '.join(risk.affected_systems)}")
            console.print(f"    [dim]Mitigation:[/dim] {risk.mitigation}")
            console.print()


@app.command()
def sector(
    sector_name: str | None = typer.Argument(
        None,
        help="Sector to analyze (space, automotive, industrial, energy, healthcare, financial, telecom)",
    ),
    list_sectors: bool = typer.Option(
        False,
        "--list",
        "-l",
        help="List all critical infrastructure sectors",
    ),
    deadlines: bool = typer.Option(
        False,
        "--deadlines",
        "-d",
        help="Show compliance deadlines across all sectors",
    ),
) -> None:
    """
    Critical infrastructure sector-specific PQC guidance.

    Shows sector-specific constraints, regulations, and recommendations
    for space, automotive, industrial OT, energy, healthcare, financial,
    and telecommunications sectors.

    Examples:

        pqc-bench sector --list

        pqc-bench sector space

        pqc-bench sector automotive

        pqc-bench sector --deadlines
    """
    from rich import box
    from rich.table import Table

    from .data.critical_infrastructure import (
        SECTOR_PROFILES,
        MigrationUrgency,
        get_compliance_deadlines,
        get_sector_profile,
    )

    console.print()

    if deadlines:
        console.print("[bold]PQC Compliance Deadlines by Sector[/bold]")
        console.print("═" * 70)
        console.print()

        all_deadlines = get_compliance_deadlines()
        if not all_deadlines:
            console.print("[dim]No specific deadlines found.[/dim]")
            return

        table = Table(box=box.ROUNDED, show_header=True, header_style="bold")
        table.add_column("Sector")
        table.add_column("Framework")
        table.add_column("Deadline")

        for sector_name_dl, framework, deadline in all_deadlines:
            table.add_row(sector_name_dl, framework, deadline)

        console.print(table)
        console.print()
        return

    if list_sectors or not sector_name:
        console.print("[bold]Critical Infrastructure Sectors[/bold]")
        console.print("═" * 70)
        console.print()
        console.print("[dim]Sector-specific PQC guidance based on real constraints and regulations.[/dim]")
        console.print()

        table = Table(box=box.ROUNDED, show_header=True, header_style="bold")
        table.add_column("Sector")
        table.add_column("Urgency")
        table.add_column("SNDL Risk")
        table.add_column("Equipment Lifecycle")
        table.add_column("Key Constraint")

        for profile in SECTOR_PROFILES.values():
            urgency_styles = {
                MigrationUrgency.CRITICAL: "[red]CRITICAL[/red]",
                MigrationUrgency.HIGH: "[yellow]HIGH[/yellow]",
                MigrationUrgency.MEDIUM: "[blue]MEDIUM[/blue]",
                MigrationUrgency.PLANNING: "[dim]PLANNING[/dim]",
            }
            urgency_str = urgency_styles.get(profile.urgency, str(profile.urgency.value))

            sndl_styles = {
                "extreme": "[red]EXTREME[/red]",
                "high": "[yellow]HIGH[/yellow]",
                "medium": "[blue]MEDIUM[/blue]",
                "low": "[green]LOW[/green]",
            }
            sndl_str = sndl_styles.get(profile.sndl_risk, profile.sndl_risk)

            key_constraint = profile.constraints[0].name if profile.constraints else "-"

            table.add_row(
                profile.name,
                urgency_str,
                sndl_str,
                f"{profile.equipment_lifecycle_years}y",
                key_constraint,
            )

        console.print(table)
        console.print()
        console.print("[dim]Run: pqc-bench sector <sector_id> for detailed guidance[/dim]")
        console.print("[dim]Sector IDs: space, automotive, industrial, energy, healthcare, financial, telecom[/dim]")
        console.print()
        return

    # Map short names to sector IDs
    sector_map = {
        "space": "space_aerospace",
        "aerospace": "space_aerospace",
        "satellite": "space_aerospace",
        "automotive": "automotive",
        "vehicle": "automotive",
        "ev": "automotive",
        "v2x": "automotive",
        "industrial": "industrial_ot",
        "ot": "industrial_ot",
        "scada": "industrial_ot",
        "ics": "industrial_ot",
        "energy": "energy_utilities",
        "utilities": "energy_utilities",
        "power": "energy_utilities",
        "grid": "energy_utilities",
        "healthcare": "healthcare",
        "medical": "healthcare",
        "hospital": "healthcare",
        "financial": "financial",
        "banking": "financial",
        "finance": "financial",
        "payments": "financial",
        "telecom": "telecommunications",
        "telecommunications": "telecommunications",
        "5g": "telecommunications",
        "mobile": "telecommunications",
    }

    sector_id = sector_map.get(sector_name.lower(), sector_name.lower())
    profile = get_sector_profile(sector_id)

    if not profile:
        console.print(f"[red]Unknown sector: {sector_name}[/red]")
        console.print()
        console.print("Available sectors:")
        for sid in SECTOR_PROFILES.keys():
            console.print(f"  • {sid}")
        raise typer.Exit(1)

    # Header
    console.print(f"[bold]{profile.name}[/bold]")
    console.print("═" * 70)
    console.print()
    console.print(f"[dim]{profile.description}[/dim]")
    console.print()

    # Urgency and risk
    urgency_styles = {
        MigrationUrgency.CRITICAL: "[bold red]CRITICAL[/bold red]",
        MigrationUrgency.HIGH: "[bold yellow]HIGH[/bold yellow]",
        MigrationUrgency.MEDIUM: "[blue]MEDIUM[/blue]",
        MigrationUrgency.PLANNING: "[dim]PLANNING[/dim]",
    }
    console.print(f"[bold]Migration Urgency:[/bold] {urgency_styles.get(profile.urgency, str(profile.urgency.value))}")
    console.print(f"[bold]SNDL Risk:[/bold] {profile.sndl_risk.upper()}")
    console.print(f"[bold]Data Lifespan:[/bold] {profile.data_lifespan_years} years")
    console.print(f"[bold]Equipment Lifecycle:[/bold] {profile.equipment_lifecycle_years} years")
    console.print()

    # Regulations
    if profile.regulations:
        console.print("[bold]Regulatory Framework[/bold]")
        console.print("─" * 50)
        for reg in profile.regulations:
            req_style = {
                "mandatory": "[red]MANDATORY[/red]",
                "recommended": "[yellow]RECOMMENDED[/yellow]",
                "none": "[dim]Not yet[/dim]",
            }
            console.print(f"  • [cyan]{reg.name}[/cyan] ({reg.authority})")
            console.print(f"    PQC Requirement: {req_style.get(reg.pqc_requirement, reg.pqc_requirement)}")
            if reg.deadline:
                console.print(f"    Deadline: [bold]{reg.deadline}[/bold]")
            if reg.notes:
                console.print(f"    [dim]{reg.notes}[/dim]")
            console.print()

    # Technical constraints
    if profile.constraints:
        console.print("[bold]Technical Constraints[/bold]")
        console.print("─" * 50)
        for constraint in profile.constraints:
            severity_colors = {"blocking": "red", "major": "yellow", "minor": "dim"}
            sev_color = severity_colors.get(constraint.severity, "white")
            console.print(f"  [{sev_color}]{constraint.severity.upper()}[/{sev_color}]: {constraint.name}")
            console.print(f"    {constraint.description}")
            console.print(f"    [dim]Impact:[/dim] {constraint.impact}")
            console.print()

    # Recommendations
    console.print("[bold]Algorithm Recommendations[/bold]")
    console.print("─" * 50)
    console.print(f"  KEM: [green]{profile.recommended_kem}[/green]")
    console.print(f"  Signature: [green]{profile.recommended_sig}[/green]")
    if profile.recommended_hybrid_kem:
        console.print(f"  Hybrid KEM: [cyan]{profile.recommended_hybrid_kem}[/cyan]")
    if profile.recommended_hybrid_sig:
        console.print(f"  Hybrid Sig: [cyan]{profile.recommended_hybrid_sig}[/cyan]")
    console.print()

    # Migration priority
    if profile.migration_priority:
        console.print("[bold]Migration Priority[/bold]")
        console.print("─" * 50)
        for i, priority in enumerate(profile.migration_priority, 1):
            console.print(f"  {i}. {priority}")
        console.print()

    # Special considerations
    if profile.special_considerations:
        console.print("[bold]Special Considerations[/bold]")
        console.print("─" * 50)
        for consideration in profile.special_considerations:
            if consideration.startswith("CRYPTO-AGILITY") or consideration.startswith("Falcon"):
                console.print(f"  [yellow]⚠ {consideration}[/yellow]")
            else:
                console.print(f"  • {consideration}")
        console.print()

    # References
    if profile.key_references:
        console.print("[bold]Key References[/bold]")
        console.print("─" * 50)
        for ref in profile.key_references:
            console.print(f"  [cyan]{ref}[/cyan]")
        console.print()


if __name__ == "__main__":
    app()
