"""
CPU Profiler and Flame Graph Generator using perf.

Wraps perf record/script and flamegraph.pl to generate flame graphs.
"""

import os
import subprocess
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class HotspotInfo:
    """Represents a CPU hotspot in the profiled binary."""
    function_name: str
    overhead_percent: float
    samples: int
    module: str


@dataclass
class CPUAnalysisResult:
    """Complete result of CPU analysis."""
    binary_path: str
    duration_seconds: float
    total_samples: int
    hotspots: list[HotspotInfo]
    flamegraph_path: Optional[str]
    raw_output: str
    error: Optional[str] = None


class CPUAnalyzer:
    """
    Analyzes CPU performance using Linux perf and generates flame graphs.
    
    Usage:
        analyzer = CPUAnalyzer()
        result = analyzer.analyze("./my_binary", duration=30)
    """
    
    def __init__(self) -> None:
        self._perf_path: Optional[str] = shutil.which("perf")
        self._flamegraph_script = self._find_flamegraph_script()
    
    def _find_flamegraph_script(self) -> Optional[str]:
        """Find flamegraph.pl script in common locations."""
        # Check bundled resource first
        package_dir = Path(__file__).parent.parent
        bundled = package_dir / "resources" / "flamegraph.pl"
        if bundled.exists():
            return str(bundled)
        
        # Check system path
        system_path = shutil.which("flamegraph.pl")
        if system_path:
            return system_path
        
        # Check common installation locations
        common_paths = [
            Path.home() / "FlameGraph" / "flamegraph.pl",
            Path("/usr/local/bin/flamegraph.pl"),
            Path("/opt/FlameGraph/flamegraph.pl"),
        ]
        for path in common_paths:
            if path.exists():
                return str(path)
        
        return None
    
    def is_available(self) -> bool:
        """Check if perf is installed and accessible."""
        return self._perf_path is not None
    
    def has_flamegraph(self) -> bool:
        """Check if flamegraph.pl is available."""
        return self._flamegraph_script is not None
    
    def analyze(
        self,
        binary_path: str,
        args: Optional[list[str]] = None,
        duration: int = 30,
        output_dir: Optional[str] = None,
        frequency: int = 99
    ) -> CPUAnalysisResult:
        """
        Run CPU profiling on the specified binary.
        
        Args:
            binary_path: Path to the executable to profile
            args: Optional command-line arguments to pass to the binary
            duration: Profiling duration in seconds (default: 30)
            output_dir: Directory for output files (default: current directory)
            frequency: Sampling frequency in Hz (default: 99)
            
        Returns:
            CPUAnalysisResult containing profiling information
        """
        if not self.is_available():
            return CPUAnalysisResult(
                binary_path=binary_path,
                duration_seconds=0,
                total_samples=0,
                hotspots=[],
                flamegraph_path=None,
                raw_output="",
                error="perf is not installed. Install with: sudo apt install linux-tools-common linux-tools-generic"
            )
        
        binary = Path(binary_path)
        if not binary.exists():
            return CPUAnalysisResult(
                binary_path=binary_path,
                duration_seconds=0,
                total_samples=0,
                hotspots=[],
                flamegraph_path=None,
                raw_output="",
                error=f"Binary not found: {binary_path}"
            )
        
        output_path = Path(output_dir) if output_dir else Path.cwd()
        output_path.mkdir(parents=True, exist_ok=True)
        
        try:
            # Step 1: Record perf data
            perf_data = output_path / "perf.data"
            record_result = self._record(binary, args, duration, frequency, perf_data)
            if record_result.returncode != 0:
                return CPUAnalysisResult(
                    binary_path=binary_path,
                    duration_seconds=duration,
                    total_samples=0,
                    hotspots=[],
                    flamegraph_path=None,
                    raw_output=record_result.stderr,
                    error=f"perf record failed: {record_result.stderr}"
                )
            
            # Step 2: Generate report for hotspots
            hotspots, total_samples, report_output = self._generate_report(perf_data)
            
            # Step 3: Generate flame graph if flamegraph.pl is available
            flamegraph_path = None
            if self.has_flamegraph():
                svg_path = output_path / f"{binary.stem}_flamegraph.svg"
                flamegraph_path = self._generate_flamegraph(perf_data, svg_path)
            
            # Cleanup perf.data
            if perf_data.exists():
                perf_data.unlink()
            
            return CPUAnalysisResult(
                binary_path=binary_path,
                duration_seconds=duration,
                total_samples=total_samples,
                hotspots=hotspots[:10],  # Top 10 hotspots
                flamegraph_path=flamegraph_path,
                raw_output=report_output
            )
            
        except Exception as e:
            return CPUAnalysisResult(
                binary_path=binary_path,
                duration_seconds=0,
                total_samples=0,
                hotspots=[],
                flamegraph_path=None,
                raw_output="",
                error=str(e)
            )
    
    def _record(
        self,
        binary: Path,
        args: Optional[list[str]],
        duration: int,
        frequency: int,
        output_file: Path
    ) -> subprocess.CompletedProcess:
        """Run perf record on the binary."""
        cmd = [
            self._perf_path,
            "record",
            "-F", str(frequency),
            "-g",  # Enable call graph
            "-o", str(output_file),
            "--", str(binary.absolute())
        ]
        if args:
            cmd.extend(args)
        
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=duration + 60  # Extra buffer for startup/shutdown
        )
    
    def _generate_report(self, perf_data: Path) -> tuple[list[HotspotInfo], int, str]:
        """Generate perf report and extract hotspots."""
        cmd = [
            self._perf_path,
            "report",
            "-i", str(perf_data),
            "--stdio",
            "--sort", "overhead,sym",
            "-n"  # Show sample counts
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        output = result.stdout
        
        hotspots: list[HotspotInfo] = []
        total_samples = 0
        
        for line in output.split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            
            # Parse lines like: "  10.50%   1234  binary  [.] function_name"
            parts = line.split()
            if len(parts) >= 5 and "%" in parts[0]:
                try:
                    overhead = float(parts[0].replace("%", ""))
                    samples = int(parts[1])
                    module = parts[2]
                    # Find function name (after [.] or [k])
                    func_idx = -1
                    for i, p in enumerate(parts):
                        if p in ("[.]", "[k]"):
                            func_idx = i + 1
                            break
                    
                    if func_idx > 0 and func_idx < len(parts):
                        func_name = " ".join(parts[func_idx:])
                        hotspots.append(HotspotInfo(
                            function_name=func_name,
                            overhead_percent=overhead,
                            samples=samples,
                            module=module
                        ))
                        total_samples += samples
                except (ValueError, IndexError):
                    continue
        
        return hotspots, total_samples, output
    
    def _generate_flamegraph(self, perf_data: Path, output_svg: Path) -> Optional[str]:
        """Generate flame graph SVG from perf data."""
        try:
            # perf script | stackcollapse-perf.pl | flamegraph.pl > output.svg
            script_result = subprocess.run(
                [self._perf_path, "script", "-i", str(perf_data)],
                capture_output=True,
                text=True
            )
            
            if script_result.returncode != 0:
                return None
            
            # Find stackcollapse-perf.pl
            flamegraph_dir = Path(self._flamegraph_script).parent
            stackcollapse = flamegraph_dir / "stackcollapse-perf.pl"
            
            if not stackcollapse.exists():
                # Try without stackcollapse (some setups)
                return None
            
            # Collapse stacks
            collapse_result = subprocess.run(
                ["perl", str(stackcollapse)],
                input=script_result.stdout,
                capture_output=True,
                text=True
            )
            
            if collapse_result.returncode != 0:
                return None
            
            # Generate flame graph
            flamegraph_result = subprocess.run(
                ["perl", self._flamegraph_script, "--title", "CPU Flame Graph"],
                input=collapse_result.stdout,
                capture_output=True,
                text=True
            )
            
            if flamegraph_result.returncode == 0:
                output_svg.write_text(flamegraph_result.stdout)
                return str(output_svg)
            
            return None
            
        except Exception:
            return None
