"""
Console Reporter using Rich library for beautiful terminal output.
"""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.syntax import Syntax
from rich import box

from ..analyzers.memory import MemoryAnalysisResult, MemoryLeak
from ..analyzers.cpu import CPUAnalysisResult, HotspotInfo
from ..analyzers.cache import CacheAnalysisResult, CacheStats
from ..analyzers.syscall import SyscallAnalysisResult, SyscallInfo
from ..analyzers.thread import ThreadAnalysisResult, ThreadIssue


class ConsoleReporter:
    """
    Formats and displays analysis results in the terminal using Rich.
    """
    
    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console()
    
    def report_memory(self, result: MemoryAnalysisResult) -> None:
        """Display memory leak analysis results."""
        if result.error:
            self.console.print(Panel(
                f"[bold red]Error:[/bold red] {result.error}",
                title="❌ Memory Analysis Failed",
                border_style="red"
            ))
            return
        
        # Summary Panel
        total_leaked = (
            result.definitely_lost_bytes +
            result.indirectly_lost_bytes +
            result.possibly_lost_bytes
        )
        
        summary = Table.grid(padding=(0, 2))
        summary.add_column(style="bold cyan")
        summary.add_column(style="white")
        summary.add_row("Binary:", result.binary_path)
        summary.add_row("Total Leaks:", str(result.total_leaks))
        summary.add_row("Definitely Lost:", self._format_bytes(result.definitely_lost_bytes))
        summary.add_row("Indirectly Lost:", self._format_bytes(result.indirectly_lost_bytes))
        summary.add_row("Possibly Lost:", self._format_bytes(result.possibly_lost_bytes))
        summary.add_row("Still Reachable:", self._format_bytes(result.still_reachable_bytes))
        
        status = "✅ No Leaks" if total_leaked == 0 else "⚠️ Leaks Detected"
        color = "green" if total_leaked == 0 else "yellow"
        
        self.console.print(Panel(
            summary,
            title=f"[bold]{status}[/bold] Memory Analysis Summary",
            border_style=color
        ))
        
        # Top 10 Leaks Table
        if result.leaks:
            self.console.print()
            self._print_leaks_table(result.leaks)
    
    def _print_leaks_table(self, leaks: list[MemoryLeak]) -> None:
        """Print table of top memory leaks."""
        table = Table(
            title="🔍 Top 10 Memory Leaks",
            box=box.ROUNDED,
            show_lines=True,
            title_style="bold magenta"
        )
        
        table.add_column("#", style="dim", width=3)
        table.add_column("Bytes", style="bold red", justify="right")
        table.add_column("Blocks", justify="right")
        table.add_column("Type", style="yellow")
        table.add_column("Location", style="cyan", overflow="fold")
        
        for i, leak in enumerate(leaks, 1):
            # Get first meaningful stack frame
            location = leak.stack_trace[0] if leak.stack_trace else "Unknown"
            
            table.add_row(
                str(i),
                self._format_bytes(leak.bytes_lost),
                str(leak.blocks),
                leak.leak_type,
                location
            )
        
        self.console.print(table)
    
    def report_cpu(self, result: CPUAnalysisResult) -> None:
        """Display CPU profiling results."""
        if result.error:
            self.console.print(Panel(
                f"[bold red]Error:[/bold red] {result.error}",
                title="❌ CPU Analysis Failed",
                border_style="red"
            ))
            return
        
        # Summary Panel
        summary = Table.grid(padding=(0, 2))
        summary.add_column(style="bold cyan")
        summary.add_column(style="white")
        summary.add_row("Binary:", result.binary_path)
        summary.add_row("Duration:", f"{result.duration_seconds}s")
        summary.add_row("Total Samples:", str(result.total_samples))
        
        if result.flamegraph_path:
            summary.add_row("Flame Graph:", f"[green]{result.flamegraph_path}[/green]")
        else:
            summary.add_row("Flame Graph:", "[dim]Not generated (flamegraph.pl not found)[/dim]")
        
        self.console.print(Panel(
            summary,
            title="[bold]🔥 CPU Analysis Summary[/bold]",
            border_style="blue"
        ))
        
        # Hotspots Table
        if result.hotspots:
            self.console.print()
            self._print_hotspots_table(result.hotspots)
    
    def _print_hotspots_table(self, hotspots: list[HotspotInfo]) -> None:
        """Print table of CPU hotspots."""
        table = Table(
            title="🎯 Top 10 CPU Hotspots",
            box=box.ROUNDED,
            show_lines=False,
            title_style="bold magenta"
        )
        
        table.add_column("#", style="dim", width=3)
        table.add_column("Overhead", style="bold red", justify="right")
        table.add_column("Samples", justify="right")
        table.add_column("Module", style="blue")
        table.add_column("Function", style="cyan", overflow="fold")
        
        for i, hotspot in enumerate(hotspots, 1):
            # Color overhead based on severity
            overhead_str = f"{hotspot.overhead_percent:.2f}%"
            if hotspot.overhead_percent > 20:
                overhead_str = f"[bold red]{overhead_str}[/bold red]"
            elif hotspot.overhead_percent > 10:
                overhead_str = f"[yellow]{overhead_str}[/yellow]"
            
            table.add_row(
                str(i),
                overhead_str,
                str(hotspot.samples),
                hotspot.module,
                hotspot.function_name
            )
        
        self.console.print(table)
    
    def _format_bytes(self, bytes_count: int) -> str:
        """Format byte count in human-readable form."""
        if bytes_count == 0:
            return "0 B"
        
        units = ["B", "KB", "MB", "GB"]
        unit_idx = 0
        value = float(bytes_count)
        
        while value >= 1024 and unit_idx < len(units) - 1:
            value /= 1024
            unit_idx += 1
        
        if unit_idx == 0:
            return f"{int(value)} {units[unit_idx]}"
        return f"{value:.2f} {units[unit_idx]}"

    def report_cache(self, result: CacheAnalysisResult) -> None:
        """Display cache analysis results."""
        if result.error:
            self.console.print(Panel(
                f"[bold red]Error:[/bold red] {result.error}",
                title="❌ Cache Analysis Failed",
                border_style="red"
            ))
            return

        # Summary Panel
        summary = Table.grid(padding=(0, 2))
        summary.add_column(style="bold cyan")
        summary.add_column(style="white")
        summary.add_row("Binary:", result.binary_path)
        summary.add_row("Duration:", f"{result.duration_seconds}s")
        summary.add_row("IPC:", f"{result.ipc:.2f}")
        summary.add_row("Branch Miss Rate:", f"{result.branch_miss_rate:.2f}%")

        self.console.print(Panel(
            summary,
            title="[bold]🚀 Cache Performance Summary[/bold]",
            border_style="magenta"
        ))

        # Cache Stats Table
        if result.cache_stats:
            self.console.print()
            table = Table(
                title="💾 Cache Statistics",
                box=box.ROUNDED,
                show_lines=True,
                title_style="bold magenta"
            )
            
            table.add_column("Level", style="bold cyan")
            table.add_column("Loads", justify="right")
            table.add_column("Load Misses", justify="right")
            table.add_column("Load Miss %", justify="right", style="bold yellow")
            table.add_column("Stores", justify="right")
            table.add_column("Store Misses", justify="right")
            table.add_column("Store Miss %", justify="right", style="bold yellow")

            for stats in result.cache_stats:
                table.add_row(
                    stats.level,
                    self._format_big_num(stats.loads),
                    self._format_big_num(stats.load_misses),
                    self._format_rate(stats.load_miss_rate),
                    self._format_big_num(stats.stores),
                    self._format_big_num(stats.store_misses),
                    self._format_rate(stats.store_miss_rate)
                )
            
            self.console.print(table)

    def report_syscall(self, result: SyscallAnalysisResult) -> None:
        """Display syscall analysis results."""
        if result.error:
            self.console.print(Panel(
                f"[bold red]Error:[/bold red] {result.error}",
                title="❌ Syscall Analysis Failed",
                border_style="red"
            ))
            return

        # Summary
        summary = Table.grid(padding=(0, 2))
        summary.add_column(style="bold cyan")
        summary.add_column(style="white")
        summary.add_row("Binary:", result.binary_path)
        summary.add_row("Total Time:", f"{result.total_time_seconds:.6f}s")
        summary.add_row("Total Calls:", str(result.total_syscalls))
        summary.add_row("Error Rate:", f"{result.error_rate:.2f}%")

        self.console.print(Panel(
            summary,
            title="[bold]⚙️ System Call Analysis[/bold]",
            border_style="blue"
        ))

        # Syscalls Table
        if result.syscalls:
            self.console.print()
            table = Table(
                title="Top System Calls by Time",
                box=box.ROUNDED,
                title_style="bold magenta"
            )
            
            table.add_column("Syscall", style="bold cyan")
            table.add_column("% Time", justify="right", style="yellow")
            table.add_column("Seconds", justify="right")
            table.add_column("Calls", justify="right")
            table.add_column("Errors", justify="right", style="red")

            for syscall in result.syscalls:
                table.add_row(
                    syscall.name,
                    f"{syscall.time_percent:.2f}%",
                    f"{syscall.time_seconds:.6f}",
                    str(syscall.calls),
                    str(syscall.errors) if syscall.errors > 0 else "-"
                )
            
            self.console.print(table)

    def report_thread(self, result: ThreadAnalysisResult) -> None:
        """Display thread analysis results."""
        if result.error:
            self.console.print(Panel(
                f"[bold red]Error:[/bold red] {result.error}",
                title="❌ Thread Analysis Failed",
                border_style="red"
            ))
            return

        # Summary
        summary = Table.grid(padding=(0, 2))
        summary.add_column(style="bold cyan")
        summary.add_column(style="white")
        summary.add_row("Binary:", result.binary_path)
        summary.add_row("Total Issues:", str(result.total_issues))
        summary.add_row("Data Races:", f"[red]{result.data_races}[/red]")
        summary.add_row("Lock Order Velocitions:", f"[red]{result.lock_order_violations}[/red]")
        summary.add_row("Mutex Errors:", f"[red]{result.mutex_errors}[/red]")

        status = "✅ Thread Safe" if result.total_issues == 0 else "⚠️ Threading Issues Detected"
        color = "green" if result.total_issues == 0 else "red"

        self.console.print(Panel(
            summary,
            title=f"[bold]{status}[/bold]",
            border_style=color
        ))

        # Issues Table
        if result.issues:
            self.console.print()
            table = Table(
                title="🧵 Threading Issues",
                box=box.ROUNDED,
                show_lines=True,
                title_style="bold magenta"
            )
            
            table.add_column("Type", style="bold red")
            table.add_column("Thread", justify="right")
            table.add_column("Description", style="white")
            table.add_column("Location", style="cyan")

            for issue in result.issues:
                location = issue.stack_trace[0] if issue.stack_trace else "Unknown"
                table.add_row(
                    issue.issue_type,
                    f"#{issue.thread_id}" if issue.thread_id is not None else "-",
                    issue.description,
                    location
                )
            
            self.console.print(table)

    def _format_rate(self, rate: float) -> str:
        """Format percentage rate."""
        if rate == 0:
            return "[green]0.00%[/green]"
        elif rate > 10:
             return f"[red]{rate:.2f}%[/red]"
        elif rate > 5:
             return f"[yellow]{rate:.2f}%[/yellow]"
        return f"{rate:.2f}%"

    def _format_big_num(self, num: int) -> str:
        """Format large numbers with commas."""
        if num == 0:
            return "-"
        return f"{num:,}"
