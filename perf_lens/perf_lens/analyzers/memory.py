"""
Memory Leak Analyzer using Valgrind.

Wraps valgrind --leak-check=full to detect and report memory leaks.
"""

import re
import subprocess
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class MemoryLeak:
    """Represents a single memory leak detected by Valgrind."""
    bytes_lost: int
    blocks: int
    leak_type: str  # "definitely lost", "indirectly lost", "possibly lost", "still reachable"
    stack_trace: list[str]


@dataclass
class MemoryAnalysisResult:
    """Complete result of memory analysis."""
    binary_path: str
    total_leaks: int
    definitely_lost_bytes: int
    indirectly_lost_bytes: int
    possibly_lost_bytes: int
    still_reachable_bytes: int
    leaks: list[MemoryLeak]
    raw_output: str
    error: Optional[str] = None


class MemoryAnalyzer:
    """
    Analyzes memory leaks in C++ binaries using Valgrind.
    
    Usage:
        analyzer = MemoryAnalyzer()
        result = analyzer.analyze("./my_binary", args=["arg1", "arg2"])
    """
    
    def __init__(self) -> None:
        self._valgrind_path: Optional[str] = shutil.which("valgrind")
    
    def is_available(self) -> bool:
        """Check if Valgrind is installed and accessible."""
        return self._valgrind_path is not None
    
    def analyze(
        self,
        binary_path: str,
        args: Optional[list[str]] = None,
        timeout: int = 300
    ) -> MemoryAnalysisResult:
        """
        Run memory leak analysis on the specified binary.
        
        Args:
            binary_path: Path to the executable to analyze
            args: Optional command-line arguments to pass to the binary
            timeout: Maximum execution time in seconds (default: 5 minutes)
            
        Returns:
            MemoryAnalysisResult containing leak information
        """
        if not self.is_available():
            return MemoryAnalysisResult(
                binary_path=binary_path,
                total_leaks=0,
                definitely_lost_bytes=0,
                indirectly_lost_bytes=0,
                possibly_lost_bytes=0,
                still_reachable_bytes=0,
                leaks=[],
                raw_output="",
                error="Valgrind is not installed. Install with: sudo apt install valgrind"
            )
        
        binary = Path(binary_path)
        if not binary.exists():
            return MemoryAnalysisResult(
                binary_path=binary_path,
                total_leaks=0,
                definitely_lost_bytes=0,
                indirectly_lost_bytes=0,
                possibly_lost_bytes=0,
                still_reachable_bytes=0,
                leaks=[],
                raw_output="",
                error=f"Binary not found: {binary_path}"
            )
        
        # Build valgrind command
        cmd = [
            self._valgrind_path,
            "--leak-check=full",
            "--show-leak-kinds=all",
            "--track-origins=yes",
            "--verbose",
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
            # Valgrind outputs to stderr
            output = result.stderr
            return self._parse_output(binary_path, output)
        except subprocess.TimeoutExpired:
            return MemoryAnalysisResult(
                binary_path=binary_path,
                total_leaks=0,
                definitely_lost_bytes=0,
                indirectly_lost_bytes=0,
                possibly_lost_bytes=0,
                still_reachable_bytes=0,
                leaks=[],
                raw_output="",
                error=f"Analysis timed out after {timeout} seconds"
            )
        except Exception as e:
            return MemoryAnalysisResult(
                binary_path=binary_path,
                total_leaks=0,
                definitely_lost_bytes=0,
                indirectly_lost_bytes=0,
                possibly_lost_bytes=0,
                still_reachable_bytes=0,
                leaks=[],
                raw_output="",
                error=str(e)
            )
    
    def _parse_output(self, binary_path: str, output: str) -> MemoryAnalysisResult:
        """Parse Valgrind output and extract leak information."""
        leaks: list[MemoryLeak] = []
        
        # Parse leak summary
        definitely_lost = self._extract_bytes(output, r"definitely lost: ([\d,]+) bytes")
        indirectly_lost = self._extract_bytes(output, r"indirectly lost: ([\d,]+) bytes")
        possibly_lost = self._extract_bytes(output, r"possibly lost: ([\d,]+) bytes")
        still_reachable = self._extract_bytes(output, r"still reachable: ([\d,]+) bytes")
        
        # Parse individual leak records
        leak_pattern = re.compile(
            r"([\d,]+) bytes in ([\d,]+) blocks? are (definitely|indirectly|possibly) lost.*?\n"
            r"((?:==\d+==\s+(?:at|by).*?\n)+)",
            re.MULTILINE | re.DOTALL
        )
        
        for match in leak_pattern.finditer(output):
            bytes_lost = int(match.group(1).replace(",", ""))
            blocks = int(match.group(2).replace(",", ""))
            leak_type = match.group(3) + " lost"
            
            # Extract stack trace
            stack_text = match.group(4)
            stack_lines = []
            for line in stack_text.strip().split("\n"):
                # Clean up the line
                cleaned = re.sub(r"==\d+==\s+", "", line).strip()
                if cleaned:
                    stack_lines.append(cleaned)
            
            leaks.append(MemoryLeak(
                bytes_lost=bytes_lost,
                blocks=blocks,
                leak_type=leak_type,
                stack_trace=stack_lines[:10]  # Limit stack trace depth
            ))
        
        # Sort leaks by bytes lost (descending) and take top 10
        leaks.sort(key=lambda x: x.bytes_lost, reverse=True)
        top_leaks = leaks[:10]
        
        return MemoryAnalysisResult(
            binary_path=binary_path,
            total_leaks=len(leaks),
            definitely_lost_bytes=definitely_lost,
            indirectly_lost_bytes=indirectly_lost,
            possibly_lost_bytes=possibly_lost,
            still_reachable_bytes=still_reachable,
            leaks=top_leaks,
            raw_output=output
        )
    
    def _extract_bytes(self, text: str, pattern: str) -> int:
        """Extract byte count from text using regex pattern."""
        match = re.search(pattern, text)
        if match:
            return int(match.group(1).replace(",", ""))
        return 0
