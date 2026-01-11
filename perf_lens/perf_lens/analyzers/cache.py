"""
Cache Performance Analyzer using perf stat.

Analyzes L1/L2/L3 cache hit/miss rates using hardware performance counters.
"""

import re
import subprocess
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class CacheStats:
    """Cache statistics for a specific cache level."""
    level: str  # "L1d", "L1i", "L2", "L3", "LLC"
    loads: int
    load_misses: int
    stores: int
    store_misses: int
    
    @property
    def load_miss_rate(self) -> float:
        """Calculate load miss rate as percentage."""
        if self.loads == 0:
            return 0.0
        return (self.load_misses / self.loads) * 100
    
    @property
    def store_miss_rate(self) -> float:
        """Calculate store miss rate as percentage."""
        if self.stores == 0:
            return 0.0
        return (self.store_misses / self.stores) * 100


@dataclass
class CacheAnalysisResult:
    """Complete result of cache analysis."""
    binary_path: str
    duration_seconds: float
    total_cycles: int
    total_instructions: int
    ipc: float  # Instructions Per Cycle
    cache_stats: list[CacheStats]
    branch_misses: int
    branch_total: int
    raw_output: str
    error: Optional[str] = None
    
    @property
    def branch_miss_rate(self) -> float:
        """Calculate branch miss rate as percentage."""
        if self.branch_total == 0:
            return 0.0
        return (self.branch_misses / self.branch_total) * 100


class CacheAnalyzer:
    """
    Analyzes cache performance using Linux perf stat.
    
    Usage:
        analyzer = CacheAnalyzer()
        result = analyzer.analyze("./my_binary")
    """
    
    CACHE_EVENTS = [
        "cycles",
        "instructions",
        "cache-references",
        "cache-misses",
        "L1-dcache-loads",
        "L1-dcache-load-misses",
        "L1-dcache-stores",
        "L1-icache-load-misses",
        "LLC-loads",
        "LLC-load-misses",
        "LLC-stores",
        "LLC-store-misses",
        "branch-instructions",
        "branch-misses",
    ]
    
    def __init__(self) -> None:
        self._perf_path: Optional[str] = shutil.which("perf")
    
    def is_available(self) -> bool:
        """Check if perf is installed and accessible."""
        return self._perf_path is not None
    
    def analyze(
        self,
        binary_path: str,
        args: Optional[list[str]] = None,
        timeout: int = 300
    ) -> CacheAnalysisResult:
        """
        Run cache performance analysis on the specified binary.
        
        Args:
            binary_path: Path to the executable to analyze
            args: Optional command-line arguments to pass to the binary
            timeout: Maximum execution time in seconds
            
        Returns:
            CacheAnalysisResult containing cache statistics
        """
        if not self.is_available():
            return CacheAnalysisResult(
                binary_path=binary_path,
                duration_seconds=0,
                total_cycles=0,
                total_instructions=0,
                ipc=0,
                cache_stats=[],
                branch_misses=0,
                branch_total=0,
                raw_output="",
                error="perf is not installed. Install with: sudo apt install linux-tools-common linux-tools-generic"
            )
        
        binary = Path(binary_path)
        if not binary.exists():
            return CacheAnalysisResult(
                binary_path=binary_path,
                duration_seconds=0,
                total_cycles=0,
                total_instructions=0,
                ipc=0,
                cache_stats=[],
                branch_misses=0,
                branch_total=0,
                raw_output="",
                error=f"Binary not found: {binary_path}"
            )
        
        # Build perf stat command
        events = ",".join(self.CACHE_EVENTS)
        cmd = [
            self._perf_path,
            "stat",
            "-e", events,
            str(binary.absolute())
        ]
        if args:
            cmd.extend(args)
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            # perf stat outputs to stderr
            output = result.stderr
            return self._parse_output(binary_path, output)
        except subprocess.TimeoutExpired:
            return CacheAnalysisResult(
                binary_path=binary_path,
                duration_seconds=0,
                total_cycles=0,
                total_instructions=0,
                ipc=0,
                cache_stats=[],
                branch_misses=0,
                branch_total=0,
                raw_output="",
                error=f"Analysis timed out after {timeout} seconds"
            )
        except Exception as e:
            return CacheAnalysisResult(
                binary_path=binary_path,
                duration_seconds=0,
                total_cycles=0,
                total_instructions=0,
                ipc=0,
                cache_stats=[],
                branch_misses=0,
                branch_total=0,
                raw_output="",
                error=str(e)
            )
    
    def _parse_output(self, binary_path: str, output: str) -> CacheAnalysisResult:
        """Parse perf stat output and extract cache statistics."""
        stats: dict[str, int] = {}
        duration = 0.0
        
        # Parse each line for event counts
        for line in output.split("\n"):
            line = line.strip()
            if not line:
                continue
            
            # Parse duration
            duration_match = re.search(r"([\d.]+)\s+seconds time elapsed", line)
            if duration_match:
                duration = float(duration_match.group(1))
                continue
            
            # Parse event counts like "1,234,567 cache-misses"
            count_match = re.match(r"([\d,]+)\s+(\S+)", line)
            if count_match:
                count_str = count_match.group(1).replace(",", "")
                event_name = count_match.group(2)
                try:
                    stats[event_name] = int(count_str)
                except ValueError:
                    pass
        
        # Extract values
        cycles = stats.get("cycles", 0)
        instructions = stats.get("instructions", 0)
        ipc = instructions / cycles if cycles > 0 else 0
        
        # Build cache stats
        cache_stats = []
        
        # L1 Data Cache
        l1d_loads = stats.get("L1-dcache-loads", 0)
        l1d_misses = stats.get("L1-dcache-load-misses", 0)
        l1d_stores = stats.get("L1-dcache-stores", 0)
        if l1d_loads > 0 or l1d_misses > 0:
            cache_stats.append(CacheStats(
                level="L1-Data",
                loads=l1d_loads,
                load_misses=l1d_misses,
                stores=l1d_stores,
                store_misses=0
            ))
        
        # LLC (Last Level Cache, usually L3)
        llc_loads = stats.get("LLC-loads", 0)
        llc_load_misses = stats.get("LLC-load-misses", 0)
        llc_stores = stats.get("LLC-stores", 0)
        llc_store_misses = stats.get("LLC-store-misses", 0)
        if llc_loads > 0 or llc_stores > 0:
            cache_stats.append(CacheStats(
                level="LLC (L3)",
                loads=llc_loads,
                load_misses=llc_load_misses,
                stores=llc_stores,
                store_misses=llc_store_misses
            ))
        
        # Overall cache (generic)
        cache_refs = stats.get("cache-references", 0)
        cache_misses = stats.get("cache-misses", 0)
        if cache_refs > 0:
            cache_stats.append(CacheStats(
                level="Overall",
                loads=cache_refs,
                load_misses=cache_misses,
                stores=0,
                store_misses=0
            ))
        
        return CacheAnalysisResult(
            binary_path=binary_path,
            duration_seconds=duration,
            total_cycles=cycles,
            total_instructions=instructions,
            ipc=ipc,
            cache_stats=cache_stats,
            branch_misses=stats.get("branch-misses", 0),
            branch_total=stats.get("branch-instructions", 0),
            raw_output=output
        )
