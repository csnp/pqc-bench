"""
Command-line interface for PQC-Bench.

Provides natural language recommendations, algorithm details,
comparisons, and migration guidance.
"""


from typing import TypedDict

import typer
from rich.console import Console
from rich.text import Text

from . import __version__
from .core.constraints import UseCase
from .core.engine import RecommendationEngine
from .core.parser import QueryParser
from .data.algorithms import (
    ALGORITHMS,
    UNPROFILED_ALGORITHM_NAMES,
    AlgorithmProfile,
    get_algorithm,
    get_unprofiled_algorithm_id,
)
from .data.compliance import COMPLIANCE_FRAMEWORKS, get_framework
from .data.libraries import (
    ALGORITHM_FAMILY_NAMES,
    HYBRID_KEM_USE_CASE_WORDS,
    HYBRID_MODES,
    HYBRID_SIGNATURE_USE_CASE_WORDS,
    LIBRARIES,
    HybridMode,
    LibraryProfile,
    ProductionReadiness,
    get_algorithm_family,
    get_fips_certificate_for_family,
    get_hybrid_mode,
    get_hybrid_modes_for_use_case,
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
from .output.terminal import TerminalOutput, print_rule

app = typer.Typer(
    name="pqc-bench",
    help="Post-Quantum Cryptography Benchmarking and Recommendation Engine",
    add_completion=False,
)

console = Console()
terminal = TerminalOutput(console)


def _shown(value: str) -> Text:
    """A value from the command line, as a message shows it.

    A value made only of printable characters is shown as typed. Any other value is shown as repr
    writes it, in quotes and with each character that is not printable written as an escape such
    as \\n or \\x1b, so no line break or control character from the value reaches the output, and
    a value that is not valid UTF-8 is printed instead of raising UnicodeEncodeError. The console
    prints a Text without reading markup or emoji codes in it, so square brackets and :name: codes
    are shown as typed.
    """
    return Text(value if value.isprintable() else repr(value))


def version_callback(value: bool) -> None:
    """Print version and exit."""
    if value:
        console.print(f"pqc-bench {__version__}")
        raise typer.Exit()


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool | None = typer.Option(
        None,
        "--version",
        "-V",
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
    if ctx.invoked_subcommand is None:
        # The bare command prints the help and exits 0, as --help does.
        # no_args_is_help prints the help and exits 2, with click 8.3.1 and with the
        # copy of click that typer 0.29.1 carries in place of the click package.
        typer.echo(ctx.get_help(), color=ctx.color)
        raise typer.Exit()


def _require_query(query: str) -> str:
    """Reject an empty or blank query before it is parsed."""
    if not query.strip():
        raise typer.BadParameter(
            'The query is empty. Describe what you want to protect, for example: '
            'pqc-bench recommend "TLS for a web server"'
        )
    return query


@app.command()
def recommend(
    query: str = typer.Argument(
        ...,
        help="Describe your use case in natural language",
        callback=_require_query,
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
        min=1,
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
        # typer.echo writes the document unchanged; console.print would wrap
        # long lines at the console width and break the JSON.
        typer.echo(json_formatter.format(result))
    else:
        terminal.print_recommendation(result, verbose=verbose)


@app.command()
def explain(
    algorithm: str = typer.Argument(
        ...,
        help="Algorithm ID, NIST name or legacy name (e.g., ml-dsa-65, ML-KEM-768, Kyber768)",
    ),
) -> None:
    """
    Show detailed information about a specific algorithm or hybrid mode.

    Examples:

        pqc-bench explain ml-dsa-65

        pqc-bench explain ml-kem-768

        pqc-bench explain kyber768

        pqc-bench explain falcon-512

        pqc-bench explain SecP384r1MLKEM1024
    """
    algo = get_algorithm(algorithm)

    if algo is None:
        mode = get_hybrid_mode(algorithm)
        if mode is not None:
            console.print()
            _print_hybrid_mode(mode)
            return
        console.print(Text.assemble("Unknown algorithm: ", _shown(algorithm), style="red"))
        console.print()
        console.print("Available algorithms:")
        for algo_id in sorted(ALGORITHMS.keys()):
            console.print(f"  • {algo_id}")
        console.print()
        console.print("Hybrid modes:")
        for hybrid_mode in HYBRID_MODES.values():
            console.print(f"  • {hybrid_mode.name}")
        raise typer.Exit(1)

    terminal.print_algorithm_details(algo)


def _nearest_of_same_type(algo: AlgorithmProfile) -> AlgorithmProfile | None:
    """The other algorithm of ``algo``'s type whose NIST level is nearest to its own.

    A level at or above ``algo``'s is preferred to a level below it, so the result is
    not a weaker algorithm while an equal or stronger one of the same type exists.
    Algorithms that tie keep their order in ALGORITHMS.
    """
    level = algo.security.nist_level
    return min(
        (
            other
            for other in ALGORITHMS.values()
            if other.algorithm_type == algo.algorithm_type and other.id != algo.id
        ),
        key=lambda other: (other.security.nist_level < level, abs(other.security.nist_level - level)),
        default=None,
    )


def _describe_algorithm_type(algo: AlgorithmProfile) -> str:
    """What kind of algorithm ``algo`` is, as words for a sentence."""
    return "a key encapsulation mechanism (key exchange)" if algo.is_kem else "a signature scheme"


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
        console.print(Text.assemble("Unknown algorithm: ", _shown(algorithm1), style="red"))
        raise typer.Exit(1)

    if algo2 is None:
        console.print(Text.assemble("Unknown algorithm: ", _shown(algorithm2), style="red"))
        raise typer.Exit(1)

    if algo1.id == algo2.id:
        # Also reached by two names of one algorithm, such as kyber768 and ml-kem-768.
        example = _nearest_of_same_type(algo1)
        pick = (
            f"Pick a second algorithm, for example: pqc-bench compare {algo1.id} {example.id}"
            if example is not None
            else "Pick a second algorithm. To see them all: pqc-bench list"
        )
        # soft_wrap keeps this one line, so the command in it is never split across two lines.
        console.print(
            f"{algo1.names.nist_name} compared with itself: every row would be a tie. {pick}",
            soft_wrap=True,
        )
        return

    # A KEM and a signature scheme do different jobs, so no row of the two has a winner.
    same_type = algo1.algorithm_type == algo2.algorithm_type

    console.print()
    console.print(f"[bold]Comparison: {algo1.names.nist_name} vs {algo2.names.nist_name}[/bold]")
    print_rule(console, "═", 60)
    console.print()

    if not same_type:
        console.print(
            f"{algo1.names.nist_name} is {_describe_algorithm_type(algo1)} and "
            f"{algo2.names.nist_name} is {_describe_algorithm_type(algo2)}. They do different jobs "
            "and are used together, not instead of each other, so neither one wins."
        )
        console.print()

    # Create comparison table
    from rich import box
    from rich.table import Table

    table = Table(box=box.ROUNDED, show_header=True, header_style="bold")
    table.add_column("Property", style="dim")
    table.add_column(algo1.names.nist_name)
    table.add_column(algo2.names.nist_name)
    if same_type:
        table.add_column("Winner", justify="center")

    def add_row(name: str, value1: str, value2: str, winner: str) -> None:
        """Add a row to the table, with its Winner cell when the two algorithms are of one type."""
        cells = [name, value1, value2]
        if same_type:
            cells.append(winner if winner != "=" else "[dim]tie[/dim]")
        table.add_row(*cells)

    # Security Level
    winner = "=" if algo1.security.nist_level == algo2.security.nist_level else (
        algo1.names.nist_name if algo1.security.nist_level > algo2.security.nist_level
        else algo2.names.nist_name
    )
    add_row(
        "Security Level",
        f"Level {algo1.security.nist_level}",
        f"Level {algo2.security.nist_level}",
        winner,
    )

    # Public Key Size
    winner = "=" if algo1.sizes.public_key == algo2.sizes.public_key else (
        algo1.names.nist_name if algo1.sizes.public_key < algo2.sizes.public_key
        else algo2.names.nist_name
    )
    add_row(
        "Public Key",
        f"{algo1.sizes.public_key:,} bytes",
        f"{algo2.sizes.public_key:,} bytes",
        winner,
    )

    # Signature/Ciphertext Size
    if algo1.is_signature and algo2.is_signature:
        s1 = algo1.sizes.signature or 0
        s2 = algo2.sizes.signature or 0
        winner = "=" if s1 == s2 else (
            algo1.names.nist_name if s1 < s2 else algo2.names.nist_name
        )
        add_row("Signature", f"{s1:,} bytes", f"{s2:,} bytes", winner)
    elif algo1.is_kem and algo2.is_kem:
        c1 = algo1.sizes.ciphertext or 0
        c2 = algo2.sizes.ciphertext or 0
        winner = "=" if c1 == c2 else (
            algo1.names.nist_name if c1 < c2 else algo2.names.nist_name
        )
        add_row("Ciphertext", f"{c1:,} bytes", f"{c2:,} bytes", winner)

    # Constant-time
    ct1 = "[green]Yes[/green]" if algo1.security.constant_time else "[yellow]No[/yellow]"
    ct2 = "[green]Yes[/green]" if algo2.security.constant_time else "[yellow]No[/yellow]"
    winner = "=" if algo1.security.constant_time == algo2.security.constant_time else (
        algo1.names.nist_name if algo1.security.constant_time else algo2.names.nist_name
    )
    add_row("Constant-time", ct1, ct2, winner)

    # NIST Standardized
    std1 = "[green]Yes[/green]" if algo1.compliance.nist_standardized else "[yellow]No[/yellow]"
    std2 = "[green]Yes[/green]" if algo2.compliance.nist_standardized else "[yellow]No[/yellow]"
    winner = "=" if algo1.compliance.nist_standardized == algo2.compliance.nist_standardized else (
        algo1.names.nist_name if algo1.compliance.nist_standardized else algo2.names.nist_name
    )
    add_row("NIST Standard", std1, std2, winner)

    # FPU Required
    fpu1 = "[yellow]Yes[/yellow]" if algo1.requirements.requires_fpu else "[green]No[/green]"
    fpu2 = "[yellow]Yes[/yellow]" if algo2.requirements.requires_fpu else "[green]No[/green]"
    winner = "=" if algo1.requirements.requires_fpu == algo2.requirements.requires_fpu else (
        algo1.names.nist_name if not algo1.requirements.requires_fpu else algo2.names.nist_name
    )
    add_row("Requires FPU", fpu1, fpu2, winner)

    console.print(table)
    console.print()

    if not same_type:
        like_for_like: list[str] = []
        for algo in (algo1, algo2):
            other = _nearest_of_same_type(algo)
            if other is not None:
                like_for_like.append(f"pqc-bench compare {algo.id} {other.id}")
        if like_for_like:
            # soft_wrap keeps this one line, so no command in it is split across two lines.
            console.print(f"For a like-for-like comparison: {' or '.join(like_for_like)}", soft_wrap=True)
            console.print()


class _ClassicalSizes(TypedDict, total=False):
    """Signature size of a classical signature scheme, or ciphertext size of a key exchange, in bytes."""

    signature: int
    ciphertext: int


class _ClassicalAlgorithm(_ClassicalSizes):
    """A classical algorithm that migrate covers, and the PQC algorithms that replace it."""

    name: str
    type: str  # "signature" or "kem"
    pub_key: int
    recommendation: str
    alternative: str


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
    migrations: dict[str, _ClassicalAlgorithm] = {
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
        console.print(Text.assemble("Unknown classical algorithm: ", _shown(from_algo), style="red"))
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
    print_rule(console, "═", 60)
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
    print_rule(console, "─", 40)

    if classical["type"] == "signature":
        sig_diff = (pqc_algo.sizes.signature or 0) - classical["signature"]
        console.print(f"  • JWT tokens will grow by ~{sig_diff:,} bytes")
        console.print("  • Certificate chains will be significantly larger")
        console.print("  • Signing/verification performance similar or better")
    else:
        # The same computation as `impact`, against the key share of the key exchange in this table.
        handshake = calculate_tls_kem_impact(
            pqc_algo.id,
            baseline_name=classical["name"],
            baseline_key_share=classical["pub_key"],
        )
        if handshake is not None:
            console.print(f"  • TLS 1.3 handshake vs {classical['name']}, both directions:")
            console.print(f"      ClientHello       +{handshake.client_hello_delta:,} bytes (sent by the client)")
            console.print(f"      ServerHello       +{handshake.server_hello_delta:,} bytes (sent by the server)")
            console.print(f"      Total Handshake   +{handshake.total_handshake_delta:,} bytes")
            console.print(f"  • Run [cyan]pqc-bench impact {pqc_algo.id}[/cyan] for fragmentation and middlebox risk")
        console.print("  • Key exchange performance similar or better")

    console.print()

    # Alternative
    if alt_algo:
        console.print("[bold]Alternative[/bold]")
        print_rule(console, "─", 40)
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
    print_rule(console, "─", 40)
    console.print(f"  Use [green]{pqc_algo.names.nist_name}[/green] for most applications.")
    console.print()
    console.print(f"  Run [cyan]pqc-bench explain {pqc_algo.id}[/cyan] for full details.")
    console.print()


# Use cases accepted by `compliance --use-case`, mapped to whether they need
# key establishment (KEM) and signatures. Use cases that need neither are left out.
COMPLIANCE_USE_CASES: dict[str, tuple[bool, bool]] = {
    uc.value.replace("_", "-"): (uc.needs_kem, uc.needs_signature)
    for uc in UseCase
    if uc.needs_kem or uc.needs_signature
}
COMPLIANCE_USE_CASES["kem"] = (True, False)
COMPLIANCE_USE_CASES["signatures"] = (False, True)


def _describe_use_case_sides(needs_kem: bool, needs_signature: bool) -> str:
    """Name the algorithm lists a compliance use case shows."""
    if needs_kem and needs_signature:
        return "key establishment and signatures"
    if needs_kem:
        return "key establishment only"
    return "signatures only"


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
        help="Show only the algorithms this use case needs. Accepted values: "
        + ", ".join(COMPLIANCE_USE_CASES),
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
        console.print(Text.assemble("Unknown compliance framework: ", _shown(framework), style="red"))
        console.print()
        console.print("Supported frameworks:")
        for fw_id, fw_data in COMPLIANCE_FRAMEWORKS.items():
            console.print(f"  • {fw_id}: {fw_data.name}")
        raise typer.Exit(1)

    show_kem = show_signatures = True
    use_case_name = None
    if use_case is not None:
        use_case_name = use_case.strip().lower().replace("_", "-").replace(" ", "-")
        if use_case_name not in COMPLIANCE_USE_CASES:
            console.print(Text.assemble("Unknown use case: ", _shown(use_case), style="red"))
            console.print()
            console.print("Accepted use cases:")
            for name, (needs_kem, needs_signature) in COMPLIANCE_USE_CASES.items():
                console.print(f"  • {name}: {_describe_use_case_sides(needs_kem, needs_signature)}")
            raise typer.Exit(1)
        show_kem, show_signatures = COMPLIANCE_USE_CASES[use_case_name]

    console.print()
    console.print(f"[bold]{fw.name}[/bold]")
    print_rule(console, "═", 60)
    if use_case_name is not None:
        sides = _describe_use_case_sides(show_kem, show_signatures)
        console.print(f"Showing requirements for: {use_case_name} ({sides})")
    console.print()

    console.print(f"[dim]Authority:[/dim] {fw.authority}")
    console.print(f"[dim]URL:[/dim] [cyan]{fw.url}[/cyan]")
    console.print()

    console.print("[bold]Description[/bold]")
    print_rule(console, "─", 40)
    console.print(f"  {fw.description}")
    console.print()

    console.print("[bold]Algorithm Requirements[/bold]")
    print_rule(console, "─", 40)

    sections = [
        ("Key Encapsulation (KEM):", show_kem, fw.requirements.kem_algorithms),
        ("Digital Signatures:", show_signatures, fw.requirements.signature_algorithms),
    ]
    any_unprofiled = False
    for heading, shown, algo_ids in sections:
        if not (shown and algo_ids):
            continue
        console.print(f"  [dim]{heading}[/dim]")
        for algo_id in algo_ids:
            algo = get_algorithm(algo_id)
            if algo:
                console.print(f"    • {algo.names.nist_name}")
            else:
                any_unprofiled = True
                name = UNPROFILED_ALGORITHM_NAMES.get(algo_id, algo_id.upper())
                console.print(f"    • {name} [dim](not profiled)[/dim]")
    if any_unprofiled:
        console.print(
            "  [dim]Not profiled: listed by the framework, but this tool has no profile for it, "
            "so explain and compare do not cover it. pqc-bench list shows the profiled algorithms.[/dim]"
        )

    console.print(f"  [dim]Minimum Security Level:[/dim] NIST Level {fw.requirements.min_security_level}")

    if fw.requirements.notes:
        console.print(f"  [dim]Notes:[/dim] {fw.requirements.notes}")

    console.print()

    if fw.timeline:
        console.print("[bold]Timeline[/bold]")
        print_rule(console, "─", 40)
        if fw.timeline.prefer_by:
            console.print(f"  • Prefer PQC by: {fw.timeline.prefer_by}")
        if fw.timeline.require_by:
            console.print(f"  • Require PQC by: {fw.timeline.require_by}")
        if fw.timeline.exclusive_by:
            console.print(f"  • Exclusive PQC by: {fw.timeline.exclusive_by}")
        if fw.timeline.complete_by:
            console.print(f"  • Transition complete by: {fw.timeline.complete_by}")
        if fw.timeline.categories:
            console.print("  [dim]By category (prefer by / exclusive by):[/dim]")
            for cat in fw.timeline.categories:
                console.print(f"    • {cat.category}: {cat.prefer_by} / {cat.exclusive_by}")
        if fw.timeline.notes:
            console.print(f"  [dim]{fw.timeline.notes}[/dim]")
        console.print()

    if fw.applies_to:
        console.print("[bold]Applies To[/bold]")
        print_rule(console, "─", 40)
        for applies in fw.applies_to:
            console.print(f"  • {applies}")
        console.print()

    if fw.citations:
        console.print("[bold]References[/bold]")
        print_rule(console, "─", 40)
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
    wanted_type = None
    if algorithm_type is not None:
        # "kems" and "signatures" are accepted as well
        wanted_type = algorithm_type.strip().lower().removesuffix("s")
        if wanted_type not in ("kem", "signature"):
            console.print(Text.assemble("Unknown algorithm type: ", _shown(algorithm_type), style="red"))
            console.print("Valid types: kem, signature")
            raise typer.Exit(1)

    console.print()
    console.print("[bold]Available Algorithms[/bold]")
    print_rule(console, "═", 60)
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
        if wanted_type is not None and algo.algorithm_type != wanted_type:
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


def _certificate_leaves_out(lib: LibraryProfile, family: str) -> Text:
    """The line under the libraries table for a FIPS certificate that does not list ``family``.

    It names the library, the certificate and the algorithm families that certificate lists.
    """
    family_name = ALGORITHM_FAMILY_NAMES[family]
    listed = [ALGORITHM_FAMILY_NAMES[name] for name in lib.fips_cert_families or []]
    if listed:
        listed_text = listed[0] if len(listed) < 2 else f"{', '.join(listed[:-1])} and {listed[-1]}"
        scope = f"lists {listed_text}, not {family_name}"
    else:
        scope = f"does not list {family_name}"
    return Text(f"{lib.name}: FIPS certificate #{lib.fips_cert_number} {scope}.")


def _fips_column_note(family: str | None, shows_unrecorded: bool) -> str:
    """The line under the libraries table that says which certificates the FIPS column shows.

    ``family`` is the AlgorithmSupport field of --algorithm, or None when --algorithm does not
    filter the table. ``shows_unrecorded`` is true when the column shows a certificate whose
    algorithm families are not recorded, which it shows for every family. The text holds no
    markup: the family name comes from ALGORITHM_FAMILY_NAMES, not from the command line.
    """
    if family is None:
        return (
            "FIPS here means a FIPS 140-3 certificate that lists ML-KEM, ML-DSA or SLH-DSA; a library "
            "can hold FIPS 140-3 certificates for classical algorithms only and still show No."
        )
    family_name = ALGORITHM_FAMILY_NAMES[family]
    unrecorded = ", or one whose algorithm families are not recorded here" if shows_unrecorded else ""
    return (
        f"FIPS here means a FIPS 140-3 certificate that lists {family_name}{unrecorded}; a library "
        f"can hold FIPS 140-3 certificates that do not list {family_name} and still show No."
    )


def _names_known_algorithm(value: str) -> bool:
    """Whether ``value`` names an algorithm or hybrid mode this tool has data for.

    That is a profiled algorithm by ID, NIST name or legacy name, an unprofiled algorithm by ID or
    FIPS 205 name, or a hybrid mode by ID or name.
    """
    return (
        get_algorithm(value) is not None
        or get_unprofiled_algorithm_id(value) is not None
        or get_hybrid_mode(value) is not None
    )


def _library_algorithm_ids() -> list[str]:
    """The algorithm IDs, profiled and unprofiled, that libraries --algorithm finds a library for, sorted."""
    algo_ids = {*ALGORITHMS, *UNPROFILED_ALGORITHM_NAMES}
    return sorted(algo_id for algo_id in algo_ids if get_libraries_for_algorithm(algo_id))


def _no_library_passes_every_option(algorithm: str | None, production_only: bool, fips_only: bool) -> Text:
    """The line libraries prints when no library passes every option given.

    It names what each option given asks for, so the reader sees that the options were combined.
    """
    parts: list[str | Text] = ["No libraries found"]
    if algorithm:
        parts += [" supporting ", _shown(algorithm)]
    conditions = []
    if production_only:
        conditions.append("are production-ready")
    if fips_only:
        conditions.append("hold a FIPS 140-3 certificate that lists ML-KEM, ML-DSA or SLH-DSA")
    if conditions:
        parts.append(f" that {' and '.join(conditions)}")
    return Text.assemble(*parts, style="yellow")


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
        help="Show only libraries with a FIPS 140-3 certificate that lists ML-KEM, ML-DSA or SLH-DSA",
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

    liboqs is a research library and is not production-ready;
    --production lists the libraries that are.

    The options combine: a library is listed only when it passes
    each option given.

    Examples:

        pqc-bench libraries

        pqc-bench libraries --production

        pqc-bench libraries --fips

        pqc-bench libraries --algorithm ml-kem-768

        pqc-bench libraries --production --algorithm ml-kem-768
    """
    from rich import box
    from rich.table import Table

    console.print()
    console.print("[bold]Cryptographic Libraries for PQC[/bold]")
    print_rule(console, "═", 70)
    console.print()

    # Filter libraries. Each option given keeps only the libraries that pass it, so a call that
    # combines options lists the libraries that pass all of them.
    family: str | None = None  # the AlgorithmSupport field of --algorithm, when it filters the table
    libs = list(LIBRARIES.values())
    if algorithm:
        libs = get_libraries_for_algorithm(algorithm)
        if not libs and not _names_known_algorithm(algorithm):
            console.print(Text.assemble("Unknown algorithm: ", _shown(algorithm), style="red"))
            console.print()
            console.print("Available algorithms:")
            for algo_id in _library_algorithm_ids():
                console.print(f"  • {algo_id}")
            raise typer.Exit(1)
        if not libs:
            # No library supports the algorithm, and the other options only remove libraries
            console.print(Text.assemble("No libraries found supporting ", _shown(algorithm), style="yellow"))
            console.print()
            return
        family = get_algorithm_family(algorithm)
    if production_only:
        production_ready = {lib.id for lib in get_production_ready_libraries()}
        libs = [lib for lib in libs if lib.id in production_ready]
    if fips_only:
        with_fips = {lib.id for lib in get_libraries_with_fips()}
        libs = [lib for lib in libs if lib.id in with_fips]
    if not libs:
        console.print(_no_library_passes_every_option(algorithm, production_only, fips_only))
        console.print()
        return

    table = Table(box=box.ROUNDED, show_header=True, header_style="bold")
    table.add_column("Library")
    table.add_column("Production")
    table.add_column("FIPS")
    table.add_column("Notable Users")

    # A line for each certificate the FIPS column leaves out because it does not list the family
    left_out: list[Text] = []
    # Whether the column shows, for that family, a certificate whose families are not recorded
    shows_unrecorded = False
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

        # FIPS styling. Filtered by --algorithm, the column shows a certificate whose recorded
        # families include that algorithm's family, or one whose families are not recorded.
        cert = lib.fips_cert_number if family is None else get_fips_certificate_for_family(lib, family)
        if cert:
            fips = f"[green]#{cert}[/green]"
            if family is not None and lib.fips_cert_families is None:
                shows_unrecorded = True
        else:
            fips = "[dim]No[/dim]"
            if family is not None and lib.fips_cert_number:
                left_out.append(_certificate_leaves_out(lib, family))

        # Notable users
        users = ", ".join(lib.notable_users[:3]) if lib.notable_users else "-"

        table.add_row(lib.name, prod, fips, users)

    console.print(table)
    console.print()
    # Under --algorithm the note names the family the column counts, so it agrees with the lines below
    console.print(f"[dim]{_fips_column_note(family, shows_unrecorded)}[/dim]")
    console.print()

    # Say which algorithm families each certificate the FIPS column left out lists
    if left_out:
        for line in left_out:
            console.print(line)
        console.print()

    # liboqs is in the unfiltered table: say why it is not for production and what to run next
    liboqs = LIBRARIES.get("liboqs")
    if liboqs and not production_only and not fips_only:
        console.print("[bold]liboqs is not production-ready[/bold]")
        print_rule(console, "─", 40)
        console.print("  Its README says it is meant for research and prototyping, and does not")
        console.print("  recommend relying on it in production or to protect sensitive data.")
        console.print("  For production, use AWS-LC, BoringSSL or OpenSSL 3.5+.")
        console.print()
        console.print("[bold]Next step:[/bold] list the production-ready libraries")
        console.print("  [cyan]pqc-bench libraries --production[/cyan]")
        console.print()


def _print_hybrid_mode(mode: HybridMode) -> None:
    """Print one hybrid mode: components, size, support and libraries."""
    console.print(f"[bold cyan]{mode.name}[/bold cyan]")
    print_rule(console, "─", 50)
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

    if supports:
        console.print(f"  [dim]Browser/CDN support:[/dim] {', '.join(supports)}")
    else:
        console.print("  [dim]Browser/CDN support:[/dim] [yellow]Not yet[/yellow]")
    tls = "[green]Yes[/green]" if mode.tls_support else "[yellow]Not yet[/yellow]"
    console.print(f"  [dim]TLS support:[/dim] {tls}")

    if mode.ietf_reference:
        console.print(f"  [dim]IETF reference:[/dim] {mode.ietf_reference}")

    console.print(f"  [dim]Recommended until:[/dim] {mode.recommended_until}")

    if mode.libraries:
        libs = [lib.name if (lib := LIBRARIES.get(lib_id)) else lib_id for lib_id in mode.libraries]
        console.print(f"  [dim]Libraries:[/dim] {', '.join(libs)}")

    console.print()


@app.command()
def hybrid(
    use_case: str | None = typer.Option(
        None,
        "--use-case",
        "-u",
        help=f"Filter by use case: {', '.join(HYBRID_KEM_USE_CASE_WORDS)} for key exchange; "
        f"{', '.join(HYBRID_SIGNATURE_USE_CASE_WORDS)} for signatures",
    ),
) -> None:
    """
    Show hybrid cryptography modes (classical + PQC).

    Hybrid modes are the practical migration path - they provide
    security if either the classical OR PQC algorithm is secure.

    Examples:

        pqc-bench hybrid

        pqc-bench hybrid --use-case tls

        pqc-bench hybrid --use-case signature
    """
    # Filter modes
    if use_case is None:
        modes = list(HYBRID_MODES.values())
    else:
        modes = get_hybrid_modes_for_use_case(use_case)
        if not modes:
            console.print(Text.assemble("Unknown use case: ", _shown(use_case), style="red"))
            console.print()
            console.print("Accepted use cases:")
            console.print(f"  • {', '.join(HYBRID_KEM_USE_CASE_WORDS)}: hybrid key exchange")
            console.print(f"  • {', '.join(HYBRID_SIGNATURE_USE_CASE_WORDS)}: hybrid signatures")
            raise typer.Exit(1)

    console.print()
    console.print("[bold]Hybrid Cryptography Modes[/bold]")
    print_rule(console, "═", 70)
    console.print()

    console.print("[dim]Hybrid modes combine classical + PQC for defense-in-depth:[/dim]")
    console.print("[dim]If either algorithm is secure, the combination is secure.[/dim]")
    console.print()

    for mode in modes:
        _print_hybrid_mode(mode)

    console.print("[bold]Why Hybrid?[/bold]")
    print_rule(console, "─", 40)
    console.print("  1. PQC algorithms are newer; hybrid provides insurance")
    console.print("  2. X25519MLKEM768 is deployed in Chrome (since Chrome 131) and Cloudflare")
    console.print("  3. NIST and NSA recommend hybrid during transition period")
    console.print()


# Urgency levels accepted by `threat --urgency`.
URGENCY_LEVELS = ", ".join(level.value for level in ThreatUrgency)


@app.command()
def threat(
    ctx: typer.Context,
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
        help=f"Filter by urgency level ({URGENCY_LEVELS})",
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

    # Each of these options chooses a different view: a second one is rejected, not ignored.
    given = [
        option
        for option, is_given in (
            ("--list", list_types),
            ("--data-type", data_type is not None),
            ("--urgency", urgency is not None),
        )
        if is_given
    ]
    if len(given) > 1:
        # ctx.fail raises a usage error, which exits 2 and shows the command's usage line.
        # The click package is not imported for it: typer 0.29.1 installs no click distribution.
        ctx.fail(
            f"{', '.join(given[:-1])} and {given[-1]} cannot be used together: "
            "each one shows a different view. Use one of them."
        )

    console.print()
    console.print("[bold]SNDL Threat Assessment[/bold]")
    print_rule(console, "═", 70)
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
                deadline_str = f"[red]{abs(deadline)}y overdue[/red]"
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
        urgency_map = {level.value: level for level in ThreatUrgency}
        urg = urgency_map.get(urgency.lower())
        if urg is None:
            console.print(Text.assemble("Unknown urgency level: ", _shown(urgency), style="red"))
            console.print(f"Valid levels: {URGENCY_LEVELS}")
            raise typer.Exit(1)

        profiles = get_profiles_by_urgency(urg)
        if not profiles:
            # A valid level can have no profile: say so instead of printing an empty list.
            levels_in_use = ", ".join(level.value for level in ThreatUrgency if get_profiles_by_urgency(level))
            console.print(f"[yellow]No data profile has {urg.value.upper()} urgency.[/yellow]")
            console.print(f"Levels that have profiles: {levels_in_use}")
            console.print()
            return

        console.print(f"[bold]Data profiles with {urg.value.upper()} urgency:[/bold]")
        console.print()
        for profile in profiles:
            console.print(f"  • [bold]{profile.name}[/bold]")
            console.print(f"    {profile.description}")
            console.print(f"    Action: {profile.recommended_action}")
            console.print()
        return

    # Detailed assessment for specific data type
    assessment = assess_sndl_risk(data_type) if data_type is not None else None
    if not assessment:
        console.print(Text.assemble("Unknown data type: ", _shown(str(data_type)), style="red"))
        console.print()
        console.print("Available data types:")
        for profile_id in DATA_PROFILES.keys():
            console.print(f"  • {profile_id}")
        raise typer.Exit(1)

    profile = assessment.data_profile

    console.print(f"[bold]{profile.name}[/bold]")
    print_rule(console, "─", 50)
    console.print()
    console.print(f"[dim]Description:[/dim] {profile.description}")
    console.print(f"[dim]Typical lifespan:[/dim] {profile.typical_lifespan_years} years")
    console.print(f"[dim]Classification:[/dim] {profile.classification.label}")
    console.print()

    # Risk assessment
    if assessment.is_at_risk:
        console.print("[bold red]⚠ At risk[/bold red]")
    else:
        console.print("[bold green]✓ Manageable[/bold green]")

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

    if assessment.recommended_algorithm:
        console.print(f"[bold]Next step:[/bold] find a library that implements {assessment.recommended_algorithm}")
        console.print(f"  [cyan]pqc-bench libraries --algorithm {assessment.recommended_algorithm.lower()}[/cyan]")
        console.print()


@app.command()
def impact(
    algorithm: str = typer.Argument(..., help="Algorithm to analyze (e.g., ml-kem-768, ml-dsa-65)"),
    chain_length: int = typer.Option(
        3,
        "--chain-length",
        "-c",
        min=1,
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
        console.print(Text.assemble("Unknown algorithm: ", _shown(algorithm), style="red"))
        raise typer.Exit(1)

    console.print()
    console.print(f"[bold]Protocol Impact: {algo.names.nist_name}[/bold]")
    print_rule(console, "═", 70)
    console.print()

    if algo.is_kem:
        impact_data = calculate_tls_kem_impact(algorithm)
        if impact_data:
            console.print("[bold]TLS 1.3 Handshake Impact (Key Exchange)[/bold]")
            print_rule(console, "─", 50)
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
            print_rule(console, "─", 50)
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
            print_rule(console, "─", 50)

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
        print_rule(console, "─", 50)
        for risk in risks:
            severity_colors = {"low": "green", "medium": "yellow", "high": "red"}
            sev_color = severity_colors.get(risk.severity, "white")
            console.print(f"  [{sev_color}]{risk.severity.upper()}[/{sev_color}]: {risk.description}")
            console.print(f"    [dim]Affected:[/dim] {', '.join(risk.affected_systems)}")
            console.print(f"    [dim]Mitigation:[/dim] {risk.mitigation}")
            console.print()


# The name that `sector --list` and the unknown-sector error give for each sector profile,
# in the order of SECTOR_PROFILES.
SECTOR_NAMES: dict[str, str] = {
    "space": "space_aerospace",
    "automotive": "automotive",
    "industrial": "industrial_ot",
    "energy": "energy_utilities",
    "healthcare": "healthcare",
    "financial": "financial",
    "telecom": "telecommunications",
}

# Words that `sector` accepts for a sector, mapped to the sector's profile ID.
# `sector` accepts a profile ID as well.
SECTOR_ALIASES: dict[str, str] = {
    **SECTOR_NAMES,
    "aerospace": "space_aerospace",
    "satellite": "space_aerospace",
    "vehicle": "automotive",
    "ev": "automotive",
    "v2x": "automotive",
    "ot": "industrial_ot",
    "scada": "industrial_ot",
    "ics": "industrial_ot",
    "utilities": "energy_utilities",
    "power": "energy_utilities",
    "grid": "energy_utilities",
    "medical": "healthcare",
    "hospital": "healthcare",
    "banking": "financial",
    "finance": "financial",
    "payments": "financial",
    "telecommunications": "telecommunications",
    "5g": "telecommunications",
    "mobile": "telecommunications",
}


@app.command()
def sector(
    sector_name: str | None = typer.Argument(
        None,
        help=f"Sector to analyze ({', '.join(SECTOR_NAMES)})",
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
        print_rule(console, "═", 70)
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
        print_rule(console, "═", 70)
        console.print()
        console.print("[dim]Sector-specific PQC guidance based on real constraints and regulations.[/dim]")
        console.print()

        table = Table(box=box.ROUNDED, show_header=True, header_style="bold")
        # A word longer than the column is broken onto the next line instead of cut short with "…".
        table.add_column("Sector", overflow="fold")
        table.add_column("Urgency")
        table.add_column("SNDL Risk")
        # The values are a few characters wide. With the header on two lines the column needs
        # no more width than "Equipment", which leaves room for "Telecommunications" at 80 columns.
        table.add_column("Equipment\nLifecycle")
        table.add_column("Key Constraint")

        for listed in SECTOR_PROFILES.values():
            urgency_styles = {
                MigrationUrgency.CRITICAL: "[red]CRITICAL[/red]",
                MigrationUrgency.HIGH: "[yellow]HIGH[/yellow]",
                MigrationUrgency.MEDIUM: "[blue]MEDIUM[/blue]",
                MigrationUrgency.PLANNING: "[dim]PLANNING[/dim]",
            }
            urgency_str = urgency_styles.get(listed.urgency, str(listed.urgency.value))

            sndl_styles = {
                "extreme": "[red]EXTREME[/red]",
                "high": "[yellow]HIGH[/yellow]",
                "medium": "[blue]MEDIUM[/blue]",
                "low": "[green]LOW[/green]",
            }
            sndl_str = sndl_styles.get(listed.sndl_risk, listed.sndl_risk)

            key_constraint = listed.constraints[0].name if listed.constraints else "-"

            table.add_row(
                listed.name,
                urgency_str,
                sndl_str,
                f"{listed.equipment_lifecycle_years}y",
                key_constraint,
            )

        console.print(table)
        console.print()
        console.print("[dim]Run: pqc-bench sector <sector_id> for detailed guidance[/dim]")
        console.print(f"[dim]Sector IDs: {', '.join(SECTOR_NAMES)}[/dim]")
        console.print()
        return

    sector_id = SECTOR_ALIASES.get(sector_name.lower(), sector_name.lower())
    profile = get_sector_profile(sector_id)

    if not profile:
        console.print(Text.assemble("Unknown sector: ", _shown(sector_name), style="red"))
        console.print()
        console.print("Available sectors:")
        for name in SECTOR_NAMES:
            console.print(f"  • {name}")
        raise typer.Exit(1)

    # Header
    console.print(f"[bold]{profile.name}[/bold]")
    print_rule(console, "═", 70)
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
        print_rule(console, "─", 50)
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
        print_rule(console, "─", 50)
        for constraint in profile.constraints:
            severity_colors = {"blocking": "red", "major": "yellow", "minor": "dim"}
            sev_color = severity_colors.get(constraint.severity, "white")
            console.print(f"  [{sev_color}]{constraint.severity.upper()}[/{sev_color}]: {constraint.name}")
            console.print(f"    {constraint.description}")
            console.print(f"    [dim]Impact:[/dim] {constraint.impact}")
            console.print()

    # Recommendations
    console.print("[bold]Algorithm Recommendations[/bold]")
    print_rule(console, "─", 50)
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
        print_rule(console, "─", 50)
        for i, priority in enumerate(profile.migration_priority, 1):
            console.print(f"  {i}. {priority}")
        console.print()

    # Special considerations
    if profile.special_considerations:
        console.print("[bold]Special Considerations[/bold]")
        print_rule(console, "─", 50)
        for consideration in profile.special_considerations:
            if consideration.startswith("CRYPTO-AGILITY") or consideration.startswith("Falcon"):
                console.print(f"  [yellow]⚠ {consideration}[/yellow]")
            else:
                console.print(f"  • {consideration}")
        console.print()

    # References
    if profile.key_references:
        console.print("[bold]Key References[/bold]")
        print_rule(console, "─", 50)
        for ref in profile.key_references:
            console.print(f"  [cyan]{ref}[/cyan]")
        console.print()


if __name__ == "__main__":
    app()
