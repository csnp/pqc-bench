"""
Terminal output formatting using Rich.

Provides beautiful, accessible terminal output with progressive disclosure.
"""

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..core.engine import Recommendation, RecommendationResult
from ..data.algorithms import AlgorithmProfile


class TerminalOutput:
    """
    Formats recommendation results for terminal display.

    Supports multiple verbosity levels:
    - Quick: 3-4 line summary
    - Normal: Boxed recommendation with key details
    - Verbose: Full details with scoring factors and citations
    """

    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console()

    def print_recommendation(
        self,
        result: RecommendationResult,
        verbose: bool = False,
    ) -> None:
        """Print recommendation result to terminal."""
        if not result.recommendations:
            self._print_no_results(result)
            return

        primary = result.primary
        if primary is None:
            return

        if verbose:
            self._print_verbose(result)
        else:
            self._print_normal(result)

    def _print_normal(self, result: RecommendationResult) -> None:
        """Print normal (default) output."""
        primary = result.primary
        if primary is None:
            return

        algo = primary.algorithm

        # Build the recommendation panel
        content = self._build_recommendation_content(primary)

        panel = Panel(
            content,
            title="[bold]PQC-Bench Recommendation[/bold]",
            border_style="blue",
            box=box.ROUNDED,
        )
        self.console.print(panel)

        # Print alternatives
        if result.alternatives:
            self.console.print()
            self.console.print("[dim]Alternatives:[/dim]")
            for alt in result.alternatives[:2]:
                self._print_alternative_brief(alt)

        # Print follow-up commands
        self.console.print()
        self.console.print("[dim]Commands:[/dim]")
        self.console.print(f"  [cyan]pqc-bench explain {algo.id}[/cyan]  - Full algorithm details")
        if result.alternatives:
            alt_id = result.alternatives[0].algorithm.id
            self.console.print(
                f"  [cyan]pqc-bench compare {algo.id} {alt_id}[/cyan]  - Side-by-side comparison"
            )

    def _print_verbose(self, result: RecommendationResult) -> None:
        """Print verbose output with full details."""
        primary = result.primary
        if primary is None:
            return

        # Query analysis section
        self.console.print()
        self.console.print("[bold]Query Analysis[/bold]")
        self.console.print("─" * 40)
        self._print_constraints(result.constraints)
        self.console.print()

        # Primary recommendation
        content = self._build_recommendation_content(primary, verbose=True)
        panel = Panel(
            content,
            title=f"[bold]#1 Recommendation[/bold] (Score: {primary.score:.0f})",
            border_style="green",
            box=box.ROUNDED,
        )
        self.console.print(panel)

        # Scoring breakdown
        self.console.print()
        self.console.print("[bold]Scoring Factors[/bold]")
        self._print_scoring_table(primary)

        # Alternatives with details
        if result.alternatives:
            self.console.print()
            self.console.print("[bold]Alternatives[/bold]")
            for alt in result.alternatives:
                self._print_alternative_detailed(alt)

        # Citations
        self.console.print()
        self.console.print("[bold]Citations[/bold]")
        self.console.print("─" * 40)
        for citation in primary.algorithm.security.citations:
            self.console.print(f"  • {citation.title}")
            self.console.print(f"    [dim]{citation.url}[/dim]")

        # Notes
        if result.notes:
            self.console.print()
            self.console.print("[bold]Notes[/bold]")
            for note in result.notes:
                self.console.print(f"  [yellow]![/yellow] {note}")

    def _build_recommendation_content(
        self,
        rec: Recommendation,
        verbose: bool = False,
    ) -> Text:
        """Build the content for a recommendation panel."""
        algo = rec.algorithm
        text = Text()

        # Algorithm name and FIPS
        text.append(f"{algo.names.nist_name}", style="bold green")
        text.append(f"  ({algo.names.nist_fips})\n\n", style="dim")

        # Key metrics table
        text.append("Security     ", style="dim")
        text.append(f"NIST Level {algo.security.nist_level} ({algo.security.classical_bits}-bit)\n")

        if algo.is_signature and algo.sizes.signature:
            text.append("Signature    ", style="dim")
            text.append(f"{algo.sizes.signature:,} bytes\n")

        if algo.is_kem and algo.sizes.ciphertext:
            text.append("Ciphertext   ", style="dim")
            text.append(f"{algo.sizes.ciphertext:,} bytes\n")

        text.append("Public Key   ", style="dim")
        text.append(f"{algo.sizes.public_key:,} bytes\n")

        # Add a separator
        text.append("\n")

        # Reasons (green checkmarks)
        for reason in rec.reasons[:4]:
            text.append("✓ ", style="green")
            text.append(f"{reason}\n")

        # Warnings (yellow)
        if rec.warnings:
            text.append("\n")
            for warning in rec.warnings[:2]:
                text.append("⚠ ", style="yellow")
                text.append(f"{warning}\n", style="yellow")

        return text

    def _print_constraints(self, constraints) -> None:
        """Print parsed constraints."""
        if constraints.use_case:
            self.console.print(f"  • Use case:    {constraints.use_case.value}")
        if constraints.platform:
            self.console.print(f"  • Platform:    {constraints.platform.value}")
        if constraints.needs_signature:
            self.console.print("  • Needs:       Digital signatures")
        if constraints.needs_kem:
            self.console.print("  • Needs:       Key encapsulation")
        if constraints.compliance_frameworks:
            frameworks = ", ".join(f.value for f in constraints.compliance_frameworks)
            self.console.print(f"  • Compliance:  {frameworks}")
        if constraints.max_latency_ms:
            self.console.print(f"  • Latency:     ≤{constraints.max_latency_ms}ms")

    def _print_scoring_table(self, rec: Recommendation) -> None:
        """Print scoring factors as a table."""
        table = Table(box=box.SIMPLE, show_header=True, header_style="bold")
        table.add_column("Factor", style="dim")
        table.add_column("Weight", justify="right")
        table.add_column("Score", justify="right")
        table.add_column("Reason")

        for factor in rec.scoring_factors:
            score_style = "green" if factor.score >= 70 else "yellow" if factor.score >= 50 else "red"
            table.add_row(
                factor.name.title(),
                f"{factor.weight:.0%}",
                f"[{score_style}]{factor.score:.0f}[/{score_style}]",
                factor.reason,
            )

        self.console.print(table)

    def _print_alternative_brief(self, rec: Recommendation) -> None:
        """Print brief alternative recommendation."""
        algo = rec.algorithm
        warning = rec.warnings[0] if rec.warnings else ""
        self.console.print(
            f"  [dim]#{rec.rank}[/dim] {algo.names.nist_name} (Score: {rec.score:.0f}) - "
            f"[dim]{warning}[/dim]"
        )

    def _print_alternative_detailed(self, rec: Recommendation) -> None:
        """Print detailed alternative recommendation."""
        algo = rec.algorithm
        self.console.print()
        self.console.print(
            f"  [bold]#{rec.rank} {algo.names.nist_name}[/bold] (Score: {rec.score:.0f})"
        )
        for reason in rec.reasons[:2]:
            self.console.print(f"      [dim]• {reason}[/dim]")
        for warning in rec.warnings[:1]:
            self.console.print(f"      [yellow]• {warning}[/yellow]")

    def _print_no_results(self, result: RecommendationResult) -> None:
        """Print message when no algorithms match."""
        self.console.print()
        self.console.print("[yellow]No algorithms match the specified constraints.[/yellow]")
        self.console.print()

        if result.notes:
            for note in result.notes:
                self.console.print(f"  {note}")

        self.console.print()
        self.console.print("Try adjusting your requirements or run [cyan]pqc-bench --help[/cyan]")

    def print_algorithm_details(self, algo: AlgorithmProfile) -> None:
        """Print detailed information about a single algorithm."""
        # Header
        self.console.print()
        title = f"{algo.names.nist_name} ({algo.names.nist_fips})"
        self.console.print(Panel(f"[bold]{title}[/bold]", box=box.DOUBLE))

        # Identity
        self.console.print()
        self.console.print("[bold]Identity[/bold]")
        self.console.print("─" * 40)
        self.console.print(f"  NIST Name:     {algo.names.nist_name}")
        self.console.print(f"  Legacy Name:   {algo.names.legacy_name}")
        self.console.print(f"  FIPS:          {algo.names.nist_fips}")
        if algo.names.oid:
            self.console.print(f"  OID:           {algo.names.oid}")
        self.console.print(f"  Type:          {'Signature' if algo.is_signature else 'KEM'}")

        # Security
        self.console.print()
        self.console.print("[bold]Security[/bold]")
        self.console.print("─" * 40)
        self.console.print(f"  NIST Level:    {algo.security.nist_level}")
        self.console.print(f"  Classical:     {algo.security.classical_bits}-bit")
        self.console.print(f"  Quantum:       {algo.security.quantum_bits}-bit")
        self.console.print(f"  Properties:    {', '.join(algo.security.properties)}")
        self.console.print(
            f"  Constant-time: {'[green]Yes[/green]' if algo.security.constant_time else '[yellow]No[/yellow]'}"
        )

        # Caveats
        if algo.security.caveats:
            self.console.print()
            self.console.print("[bold]Caveats[/bold]")
            self.console.print("─" * 40)
            for caveat in algo.security.caveats:
                style = "yellow" if caveat.severity == "warning" else "red" if caveat.severity == "critical" else "dim"
                self.console.print(f"  [{style}]• {caveat.description}[/{style}]")
                if caveat.mitigation:
                    self.console.print(f"    [dim]Mitigation: {caveat.mitigation}[/dim]")

        # Sizes
        self.console.print()
        self.console.print("[bold]Sizes[/bold]")
        self.console.print("─" * 40)
        self.console.print(f"  Public Key:    {algo.sizes.public_key:,} bytes")
        self.console.print(f"  Private Key:   {algo.sizes.private_key:,} bytes")
        if algo.sizes.signature:
            self.console.print(f"  Signature:     {algo.sizes.signature:,} bytes")
        if algo.sizes.ciphertext:
            self.console.print(f"  Ciphertext:    {algo.sizes.ciphertext:,} bytes")
        if algo.sizes.comparison:
            self.console.print(f"  [dim]{algo.sizes.comparison}[/dim]")

        # Performance
        self.console.print()
        self.console.print("[bold]Performance[/bold]")
        self.console.print("─" * 40)

        table = Table(box=box.SIMPLE, show_header=True)
        table.add_column("Platform")
        if algo.is_kem:
            table.add_column("Keygen", justify="right")
            table.add_column("Encaps", justify="right")
            table.add_column("Decaps", justify="right")
        else:
            table.add_column("Keygen", justify="right")
            table.add_column("Sign", justify="right")
            table.add_column("Verify", justify="right")

        for platform, perf in algo.performance.items():
            if algo.is_kem:
                table.add_row(
                    platform,
                    f"{perf.keygen_ops:,}/s",
                    f"{perf.encaps_ops:,}/s" if perf.encaps_ops else "-",
                    f"{perf.decaps_ops:,}/s" if perf.decaps_ops else "-",
                )
            else:
                table.add_row(
                    platform,
                    f"{perf.keygen_ops:,}/s",
                    f"{perf.sign_ops:,}/s" if perf.sign_ops else "-",
                    f"{perf.verify_ops:,}/s" if perf.verify_ops else "-",
                )

        self.console.print(table)

        # Compliance
        self.console.print()
        self.console.print("[bold]Compliance[/bold]")
        self.console.print("─" * 40)
        self.console.print(
            f"  NIST Standard: {'[green]Yes[/green]' if algo.compliance.nist_standardized else '[yellow]No[/yellow]'}"
        )
        self.console.print(
            f"  FIPS Validated: {'[green]Yes[/green]' if algo.compliance.fips_validated else '[dim]Pending[/dim]'}"
        )

        if algo.compliance.approved_by:
            self.console.print("  Framework Approvals:")
            for approval in algo.compliance.approved_by:
                status_style = "green" if approval.status == "approved" else "yellow"
                self.console.print(
                    f"    • {approval.framework}: [{status_style}]{approval.status}[/{status_style}]"
                )

        # Implementations
        self.console.print()
        self.console.print("[bold]Implementations[/bold]")
        self.console.print("─" * 40)
        for impl in algo.requirements.implementations:
            fips_badge = " [green](FIPS)[/green]" if impl.fips_validated else ""
            self.console.print(f"  • {impl.library} {impl.version}{fips_badge}")
            self.console.print(f"    [dim]Platforms: {', '.join(impl.platforms)}[/dim]")

        # Notes
        if algo.notes:
            self.console.print()
            self.console.print("[bold]Notes[/bold]")
            self.console.print("─" * 40)
            for note in algo.notes:
                self.console.print(f"  • {note}")

        # Citations
        if algo.security.citations:
            self.console.print()
            self.console.print("[bold]References[/bold]")
            self.console.print("─" * 40)
            for citation in algo.security.citations:
                self.console.print(f"  • {citation.title}")
                self.console.print(f"    [cyan]{citation.url}[/cyan]")

        self.console.print()
