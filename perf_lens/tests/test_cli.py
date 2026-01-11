"""
Tests for the CLI module.
"""

import pytest
from click.testing import CliRunner

from perf_lens.cli import main


@pytest.fixture
def runner():
    """Create a CLI test runner."""
    return CliRunner()


class TestCLI:
    """Test CLI commands."""
    
    def test_main_help(self, runner):
        """Test that main --help works."""
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "Perf-Lens" in result.output
        assert "analyze" in result.output
    
    def test_version(self, runner):
        """Test that --version works."""
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "perf-lens" in result.output
    
    def test_analyze_help(self, runner):
        """Test that analyze --help works."""
        result = runner.invoke(main, ["analyze", "--help"])
        assert result.exit_code == 0
        assert "memory" in result.output
        assert "cpu" in result.output
    
    def test_analyze_memory_help(self, runner):
        """Test that analyze memory --help works."""
        result = runner.invoke(main, ["analyze", "memory", "--help"])
        assert result.exit_code == 0
        assert "BINARY" in result.output
        assert "--timeout" in result.output
    
    def test_analyze_cpu_help(self, runner):
        """Test that analyze cpu --help works."""
        result = runner.invoke(main, ["analyze", "cpu", "--help"])
        assert result.exit_code == 0
        assert "BINARY" in result.output
        assert "--duration" in result.output

    def test_analyze_cache_help(self, runner):
        """Test that analyze cache --help works."""
        result = runner.invoke(main, ["analyze", "cache", "--help"])
        assert result.exit_code == 0
        assert "BINARY" in result.output
        assert "--timeout" in result.output

    def test_analyze_syscall_help(self, runner):
        """Test that analyze syscall --help works."""
        result = runner.invoke(main, ["analyze", "syscall", "--help"])
        assert result.exit_code == 0
        assert "BINARY" in result.output
        assert "--timeout" in result.output

    def test_analyze_thread_help(self, runner):
        """Test that analyze thread --help works."""
        result = runner.invoke(main, ["analyze", "thread", "--help"])
        assert result.exit_code == 0
        assert "BINARY" in result.output
        assert "--timeout" in result.output

    
    def test_check_command(self, runner):
        """Test that check command works."""
        result = runner.invoke(main, ["check"])
        assert result.exit_code == 0
        assert "valgrind" in result.output
        assert "perf" in result.output


class TestAnalyzeMemoryCommand:
    """Test memory analysis command."""
    
    def test_missing_binary(self, runner):
        """Test error when binary doesn't exist."""
        result = runner.invoke(main, ["analyze", "memory", "/nonexistent/binary"])
        assert result.exit_code != 0


class TestAnalyzeCPUCommand:
    """Test CPU analysis command."""
    
    def test_missing_binary(self, runner):
        """Test error when binary doesn't exist."""
        result = runner.invoke(main, ["analyze", "cpu", "/nonexistent/binary"])
        assert result.exit_code != 0


class TestAnalyzeCacheCommand:
    """Test cache analysis command."""
    
    def test_missing_binary(self, runner):
        """Test error when binary doesn't exist."""
        result = runner.invoke(main, ["analyze", "cache", "/nonexistent/binary"])
        assert result.exit_code != 0


class TestAnalyzeSyscallCommand:
    """Test syscall analysis command."""
    
    def test_missing_binary(self, runner):
        """Test error when binary doesn't exist."""
        result = runner.invoke(main, ["analyze", "syscall", "/nonexistent/binary"])
        assert result.exit_code != 0


class TestAnalyzeThreadCommand:
    """Test thread analysis command."""
    
    def test_missing_binary(self, runner):
        """Test error when binary doesn't exist."""
        result = runner.invoke(main, ["analyze", "thread", "/nonexistent/binary"])
        assert result.exit_code != 0

