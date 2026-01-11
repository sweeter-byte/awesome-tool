"""
System Call Analyzer using strace.

Analyzes system call usage, timing, and overhead.
"""

import re
import subprocess
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class SyscallInfo:
    """Information about a specific system call."""
    name: str
    calls: int
    errors: int
    time_seconds: float
    time_percent: float


@dataclass
class SyscallAnalysisResult:
    """Complete result of system call analysis."""
    binary_path: str
    total_syscalls: int
    total_time_seconds: float
    syscalls: list[SyscallInfo]
    raw_output: str
    error: Optional[str] = None
    
    @property
    def error_rate(self) -> float:
        """Calculate overall error rate as percentage."""
        if self.total_syscalls == 0:
            return 0.0
        total_errors = sum(s.errors for s in self.syscalls)
        return (total_errors / self.total_syscalls) * 100


class SyscallAnalyzer:
    """
    Analyzes system call usage using strace.
    
    Usage:
        analyzer = SyscallAnalyzer()
        result = analyzer.analyze("./my_binary")
    """
    
    def __init__(self) -> None:
        self._strace_path: Optional[str] = shutil.which("strace")
    
    def is_available(self) -> bool:
        """Check if strace is installed and accessible."""
        return self._strace_path is not None
    
    def analyze(
        self,
        binary_path: str,
        args: Optional[list[str]] = None,
        timeout: int = 300
    ) -> SyscallAnalysisResult:
        """
        Run system call analysis on the specified binary.
        
        Args:
            binary_path: Path to the executable to analyze
            args: Optional command-line arguments to pass to the binary
            timeout: Maximum execution time in seconds
            
        Returns:
            SyscallAnalysisResult containing syscall statistics
        """
        if not self.is_available():
            return SyscallAnalysisResult(
                binary_path=binary_path,
                total_syscalls=0,
                total_time_seconds=0,
                syscalls=[],
                raw_output="",
                error="strace is not installed. Install with: sudo apt install strace"
            )
        
        binary = Path(binary_path)
        if not binary.exists():
            return SyscallAnalysisResult(
                binary_path=binary_path,
                total_syscalls=0,
                total_time_seconds=0,
                syscalls=[],
                raw_output="",
                error=f"Binary not found: {binary_path}"
            )
        
        # Build strace command with summary
        cmd = [
            self._strace_path,
            "-c",  # Summary mode
            "-S", "time",  # Sort by time
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
            # strace outputs summary to stderr
            output = result.stderr
            return self._parse_output(binary_path, output)
        except subprocess.TimeoutExpired:
            return SyscallAnalysisResult(
                binary_path=binary_path,
                total_syscalls=0,
                total_time_seconds=0,
                syscalls=[],
                raw_output="",
                error=f"Analysis timed out after {timeout} seconds"
            )
        except Exception as e:
            return SyscallAnalysisResult(
                binary_path=binary_path,
                total_syscalls=0,
                total_time_seconds=0,
                syscalls=[],
                raw_output="",
                error=str(e)
            )
    
    def _parse_output(self, binary_path: str, output: str) -> SyscallAnalysisResult:
        """Parse strace -c output and extract syscall statistics."""
        syscalls: list[SyscallInfo] = []
        total_time = 0.0
        total_calls = 0
        
        # Parse strace summary table
        # Format: % time    seconds  usecs/call     calls    errors syscall
        for line in output.split("\n"):
            line = line.strip()
            if not line or line.startswith("%") or line.startswith("-"):
                continue
            
            # Parse total line
            if line.startswith("total"):
                total_match = re.match(r"total\s+\S+\s+([\d.]+)\s+\S+\s+(\d+)", line)
                if total_match:
                    total_time = float(total_match.group(1))
                    total_calls = int(total_match.group(2))
                continue
            
            # Parse syscall lines
            # Format: "  5.26    0.000052          17         3           write"
            parts = line.split()
            if len(parts) >= 5:
                try:
                    time_percent = float(parts[0])
                    time_seconds = float(parts[1])
                    calls = int(parts[3])
                    
                    # Check if errors column exists
                    if len(parts) == 6:
                        errors = int(parts[4])
                        name = parts[5]
                    else:
                        errors = 0
                        name = parts[4]
                    
                    syscalls.append(SyscallInfo(
                        name=name,
                        calls=calls,
                        errors=errors,
                        time_seconds=time_seconds,
                        time_percent=time_percent
                    ))
                except (ValueError, IndexError):
                    continue
        
        # Sort by time (descending)
        syscalls.sort(key=lambda x: x.time_seconds, reverse=True)
        
        return SyscallAnalysisResult(
            binary_path=binary_path,
            total_syscalls=total_calls,
            total_time_seconds=total_time,
            syscalls=syscalls[:15],  # Top 15 syscalls
            raw_output=output
        )
