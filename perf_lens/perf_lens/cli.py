"""
Perf-Lens CLI Entry Point.

Provides user-friendly commands for C++ performance analysis.
"""

import click
from rich.console import Console

from . import __version__
from .analyzers import (
    MemoryAnalyzer,
    CPUAnalyzer,
    CacheAnalyzer,
    SyscallAnalyzer,
    ThreadAnalyzer,
)
from .reporters import ConsoleReporter


console = Console()


@click.group()
@click.version_option(version=__version__, prog_name="perf-lens")
def main() -> None:
    """
    🔍 Perf-Lens: Intelligent C++ Performance Analysis Tool
    
    Simplify complex Linux analysis tools (perf, valgrind) through
    a user-friendly interface with one-click analysis and visualized reports.
    """
    pass


@main.group()
def analyze() -> None:
    """Run performance analysis on a binary."""
    pass


@analyze.command("memory")
@click.argument("binary", type=click.Path(exists=True))
@click.option(
    "--args", "-a",
    multiple=True,
    help="Arguments to pass to the binary (can be used multiple times)"
)
@click.option(
    "--timeout", "-t",
    default=300,
    type=int,
    help="Maximum execution time in seconds (default: 300)"
)
@click.option(
    "--raw",
    is_flag=True,
    help="Show raw Valgrind output"
)
def analyze_memory(binary: str, args: tuple[str, ...], timeout: int, raw: bool) -> None:
    """
    Analyze memory leaks using Valgrind.
    
    Example:
        perf-lens analyze memory ./my_program
        perf-lens analyze memory ./my_program -a arg1 -a arg2
    """
    reporter = ConsoleReporter(console)
    
    console.print(f"[bold blue]🔍 Analyzing memory leaks in:[/bold blue] {binary}")
    console.print()
    
    analyzer = MemoryAnalyzer()
    
    if not analyzer.is_available():
        console.print("[bold red]Error:[/bold red] Valgrind is not installed.")
        console.print("[dim]Install with: sudo apt install valgrind[/dim]")
        raise SystemExit(1)
    
    with console.status("[bold green]Running Valgrind analysis..."):
        result = analyzer.analyze(binary, list(args) if args else None, timeout)
    
    reporter.report_memory(result)
    
    if raw and result.raw_output:
        console.print()
        console.print("[bold]Raw Valgrind Output:[/bold]")
        console.print(result.raw_output)


@analyze.command("cpu")
@click.argument("binary", type=click.Path(exists=True))
@click.option(
    "--args", "-a",
    multiple=True,
    help="Arguments to pass to the binary (can be used multiple times)"
)
@click.option(
    "--duration", "-d",
    default=30,
    type=int,
    help="Profiling duration in seconds (default: 30)"
)
@click.option(
    "--output", "-o",
    type=click.Path(),
    default=".",
    help="Output directory for flame graph SVG (default: current directory)"
)
@click.option(
    "--frequency", "-f",
    default=99,
    type=int,
    help="Sampling frequency in Hz (default: 99)"
)
@click.option(
    "--raw",
    is_flag=True,
    help="Show raw perf output"
)
def analyze_cpu(
    binary: str,
    args: tuple[str, ...],
    duration: int,
    output: str,
    frequency: int,
    raw: bool
) -> None:
    """
    Analyze CPU performance and generate flame graphs.
    
    Example:
        perf-lens analyze cpu ./my_program
        perf-lens analyze cpu ./my_program -d 60 -o ./reports
    """
    reporter = ConsoleReporter(console)
    
    console.print(f"[bold blue]🔥 Profiling CPU usage in:[/bold blue] {binary}")
    console.print(f"[dim]Duration: {duration}s, Frequency: {frequency}Hz[/dim]")
    console.print()
    
    analyzer = CPUAnalyzer()
    
    if not analyzer.is_available():
        console.print("[bold red]Error:[/bold red] perf is not installed.")
        console.print("[dim]Install with: sudo apt install linux-tools-common linux-tools-generic[/dim]")
        raise SystemExit(1)
    
    if not analyzer.has_flamegraph():
        console.print("[yellow]Warning:[/yellow] flamegraph.pl not found. Flame graph will not be generated.")
        console.print("[dim]Download from: https://github.com/brendangregg/FlameGraph[/dim]")
        console.print()
    
    with console.status("[bold green]Recording CPU samples..."):
        result = analyzer.analyze(
            binary,
            list(args) if args else None,
            duration,
            output,
            frequency
        )
    
    reporter.report_cpu(result)
    
    if raw and result.raw_output:
        console.print()
        console.print("[bold]Raw perf Output:[/bold]")
        console.print(result.raw_output)
@analyze.command("cache")
@click.argument("binary", type=click.Path(exists=True))
@click.option(
    "--args", "-a",
    multiple=True,
    help="Arguments to pass to the binary (can be used multiple times)"
)
@click.option(
    "--timeout", "-t",
    default=300,
    type=int,
    help="Maximum execution time in seconds (default: 300)"
)
@click.option(
    "--raw",
    is_flag=True,
    help="Show raw perf stat output"
)
def analyze_cache(binary: str, args: tuple[str, ...], timeout: int, raw: bool) -> None:
    """
    Analyze cache performance using perf stat.
    
    Generates L1/L3 cache hit/miss rates and branch prediction statistics.
    """
    reporter = ConsoleReporter(console)
    
    console.print(f"[bold blue]🚀 Analyzing cache performance in:[/bold blue] {binary}")
    console.print()
    
    analyzer = CacheAnalyzer()
    
    if not analyzer.is_available():
        console.print("[bold red]Error:[/bold red] perf is not installed.")
        console.print("[dim]Install with: sudo apt install linux-tools-common linux-tools-generic[/dim]")
        raise SystemExit(1)
    
    with console.status("[bold green]Running perf stat..."):
        result = analyzer.analyze(binary, list(args) if args else None, timeout)
    
    reporter.report_cache(result)
    
    if raw and result.raw_output:
        console.print()
        console.print("[bold]Raw perf Output:[/bold]")
        console.print(result.raw_output)


@analyze.command("syscall")
@click.argument("binary", type=click.Path(exists=True))
@click.option(
    "--args", "-a",
    multiple=True,
    help="Arguments to pass to the binary (can be used multiple times)"
)
@click.option(
    "--timeout", "-t",
    default=300,
    type=int,
    help="Maximum execution time in seconds (default: 300)"
)
@click.option(
    "--raw",
    is_flag=True,
    help="Show raw strace output"
)
def analyze_syscall(binary: str, args: tuple[str, ...], timeout: int, raw: bool) -> None:
    """
    Analyze system call overhead using strace.
    
    Show slowest syscalls and error rates.
    """
    reporter = ConsoleReporter(console)
    
    console.print(f"[bold blue]⚙️ Analyzing system call overhead in:[/bold blue] {binary}")
    console.print()
    
    analyzer = SyscallAnalyzer()
    
    if not analyzer.is_available():
        console.print("[bold red]Error:[/bold red] strace is not installed.")
        console.print("[dim]Install with: sudo apt install strace[/dim]")
        raise SystemExit(1)
    
    with console.status("[bold green]Running strace..."):
        result = analyzer.analyze(binary, list(args) if args else None, timeout)
    
    reporter.report_syscall(result)
    
    if raw and result.raw_output:
        console.print()
        console.print("[bold]Raw strace Output:[/bold]")
        console.print(result.raw_output)


@analyze.command("thread")
@click.argument("binary", type=click.Path(exists=True))
@click.option(
    "--args", "-a",
    multiple=True,
    help="Arguments to pass to the binary (can be used multiple times)"
)
@click.option(
    "--timeout", "-t",
    default=600,
    type=int,
    help="Maximum execution time in seconds (default: 600)"
)
@click.option(
    "--raw",
    is_flag=True,
    help="Show raw Helgrind output"
)
def analyze_thread(binary: str, args: tuple[str, ...], timeout: int, raw: bool) -> None:
    """
    Analyze threading issues using Helgrind.
    
    Detects data races, deadlocks, and mutex errors.
    """
    reporter = ConsoleReporter(console)
    
    console.print(f"[bold blue]🧵 Analyzing threading issues in:[/bold blue] {binary}")
    console.print()
    
    analyzer = ThreadAnalyzer()
    
    if not analyzer.is_available():
        console.print("[bold red]Error:[/bold red] Valgrind is not installed.")
        console.print("[dim]Install with: sudo apt install valgrind[/dim]")
        raise SystemExit(1)
    
    with console.status("[bold green]Running Helgrind..."):
        result = analyzer.analyze(binary, list(args) if args else None, timeout)
    
    reporter.report_thread(result)
    
    if raw and result.raw_output:
        console.print()
        console.print("[bold]Raw Helgrind Output:[/bold]")
        console.print(result.raw_output)
@main.command("check")
def check_dependencies() -> None:
    """Check if required tools are installed."""
    from rich.table import Table
    
    table = Table(title="🔧 Dependency Check")
    table.add_column("Tool", style="cyan")
    table.add_column("Status")
    table.add_column("Install Command", style="dim")
    
    # Check Valgrind
    memory_analyzer = MemoryAnalyzer()
    if memory_analyzer.is_available():
        table.add_row("valgrind", "[green]✓ Installed[/green]", "")
    else:
        table.add_row("valgrind", "[red]✗ Not Found[/red]", "sudo apt install valgrind")
    
    # Check perf
    cpu_analyzer = CPUAnalyzer()
    if cpu_analyzer.is_available():
        table.add_row("perf", "[green]✓ Installed[/green]", "")
    else:
        table.add_row("perf", "[red]✗ Not Found[/red]", "sudo apt install linux-tools-common linux-tools-generic")
    
    # Check flamegraph.pl
    if cpu_analyzer.has_flamegraph():
        table.add_row("flamegraph.pl", "[green]✓ Found[/green]", "")
    else:
        table.add_row("flamegraph.pl", "[yellow]○ Optional[/yellow]", "git clone https://github.com/brendangregg/FlameGraph")

    # Check strace
    syscall_analyzer = SyscallAnalyzer()
    if syscall_analyzer.is_available():
        table.add_row("strace", "[green]✓ Installed[/green]", "")
    else:
        table.add_row("strace", "[red]✗ Not Found[/red]", "sudo apt install strace")
    
    console.print(table)


if __name__ == "__main__":
    main()
