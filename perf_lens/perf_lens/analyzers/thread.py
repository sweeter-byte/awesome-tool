"""
Thread Analyzer using Valgrind Helgrind.

Detects threading issues: data races, deadlocks, lock order violations.
"""

import re
import subprocess
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class ThreadIssue:
    """Represents a threading issue detected by Helgrind."""
    issue_type: str  # "data race", "lock order violation", "mutex error"
    description: str
    stack_trace: list[str]
    thread_id: Optional[int] = None


@dataclass
class ThreadAnalysisResult:
    """Complete result of thread analysis."""
    binary_path: str
    total_issues: int
    data_races: int
    lock_order_violations: int
    mutex_errors: int
    issues: list[ThreadIssue]
    raw_output: str
    error: Optional[str] = None


class ThreadAnalyzer:
    """
    Analyzes threading issues using Valgrind Helgrind.
    
    Detects:
    - Data races (concurrent access to shared memory)
    - Lock order violations (potential deadlocks)
    - Mutex errors (double locks, unlocking unowned locks)
    
    Usage:
        analyzer = ThreadAnalyzer()
        result = analyzer.analyze("./my_threaded_binary")
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
        timeout: int = 600
    ) -> ThreadAnalysisResult:
        """
        Run thread analysis on the specified binary.
        
        Args:
            binary_path: Path to the executable to analyze
            args: Optional command-line arguments to pass to the binary
            timeout: Maximum execution time in seconds (default: 10 minutes)
            
        Returns:
            ThreadAnalysisResult containing detected threading issues
        """
        if not self.is_available():
            return ThreadAnalysisResult(
                binary_path=binary_path,
                total_issues=0,
                data_races=0,
                lock_order_violations=0,
                mutex_errors=0,
                issues=[],
                raw_output="",
                error="Valgrind is not installed. Install with: sudo apt install valgrind"
            )
        
        binary = Path(binary_path)
        if not binary.exists():
            return ThreadAnalysisResult(
                binary_path=binary_path,
                total_issues=0,
                data_races=0,
                lock_order_violations=0,
                mutex_errors=0,
                issues=[],
                raw_output="",
                error=f"Binary not found: {binary_path}"
            )
        
        # Build helgrind command
        cmd = [
            self._valgrind_path,
            "--tool=helgrind",
            "--history-level=full",
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
            return ThreadAnalysisResult(
                binary_path=binary_path,
                total_issues=0,
                data_races=0,
                lock_order_violations=0,
                mutex_errors=0,
                issues=[],
                raw_output="",
                error=f"Analysis timed out after {timeout} seconds"
            )
        except Exception as e:
            return ThreadAnalysisResult(
                binary_path=binary_path,
                total_issues=0,
                data_races=0,
                lock_order_violations=0,
                mutex_errors=0,
                issues=[],
                raw_output="",
                error=str(e)
            )
    
    def _parse_output(self, binary_path: str, output: str) -> ThreadAnalysisResult:
        """Parse Helgrind output and extract threading issues."""
        issues: list[ThreadIssue] = []
        data_races = 0
        lock_violations = 0
        mutex_errors = 0
        
        # Split on error markers
        error_blocks = re.split(r"==\d+==\s*\n==\d+== ", output)
        
        for block in error_blocks:
            if "Possible data race" in block or "data race" in block.lower():
                issue = self._parse_issue_block(block, "Data Race")
                if issue:
                    issues.append(issue)
                    data_races += 1
            elif "lock order" in block.lower():
                issue = self._parse_issue_block(block, "Lock Order Violation")
                if issue:
                    issues.append(issue)
                    lock_violations += 1
            elif "mutex" in block.lower() and ("error" in block.lower() or "invalid" in block.lower()):
                issue = self._parse_issue_block(block, "Mutex Error")
                if issue:
                    issues.append(issue)
                    mutex_errors += 1
        
        # Parse error summary if present
        summary_match = re.search(r"ERROR SUMMARY: (\d+) errors", output)
        total_errors = int(summary_match.group(1)) if summary_match else len(issues)
        
        return ThreadAnalysisResult(
            binary_path=binary_path,
            total_issues=total_errors,
            data_races=data_races,
            lock_order_violations=lock_violations,
            mutex_errors=mutex_errors,
            issues=issues[:10],  # Top 10 issues
            raw_output=output
        )
    
    def _parse_issue_block(self, block: str, issue_type: str) -> Optional[ThreadIssue]:
        """Parse a single issue block from Helgrind output."""
        lines = block.strip().split("\n")
        if not lines:
            return None
        
        # First line is usually the description
        description = lines[0].strip()
        description = re.sub(r"^==\d+==\s*", "", description)
        
        # Extract stack trace
        stack_trace = []
        thread_id = None
        
        for line in lines[1:]:
            # Look for thread ID
            thread_match = re.search(r"Thread #(\d+)", line)
            if thread_match:
                thread_id = int(thread_match.group(1))
            
            # Look for stack frames
            cleaned = re.sub(r"==\d+==\s+", "", line).strip()
            if cleaned.startswith(("at ", "by ")):
                stack_trace.append(cleaned)
        
        if description:
            return ThreadIssue(
                issue_type=issue_type,
                description=description[:200],  # Truncate long descriptions
                stack_trace=stack_trace[:5],  # Limit stack depth
                thread_id=thread_id
            )
        return None
