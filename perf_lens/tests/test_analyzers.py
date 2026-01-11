"""
Tests for analyzer modules.
"""

import pytest
from unittest.mock import patch, MagicMock

from perf_lens.analyzers.memory import MemoryAnalyzer, MemoryAnalysisResult
from perf_lens.analyzers.cpu import CPUAnalyzer, CPUAnalysisResult
from perf_lens.analyzers.cache import CacheAnalyzer
from perf_lens.analyzers.syscall import SyscallAnalyzer
from perf_lens.analyzers.thread import ThreadAnalyzer


class TestMemoryAnalyzer:
    """Test MemoryAnalyzer class."""
    
    def test_init(self):
        """Test analyzer initialization."""
        analyzer = MemoryAnalyzer()
        assert hasattr(analyzer, "_valgrind_path")
    
    def test_analyze_nonexistent_binary(self):
        """Test analyzing a non-existent binary."""
        analyzer = MemoryAnalyzer()
        result = analyzer.analyze("/nonexistent/binary")
        assert result.error is not None
        assert "not found" in result.error.lower() or "not installed" in result.error.lower()
    
    @patch("shutil.which")
    def test_valgrind_not_installed(self, mock_which):
        """Test behavior when valgrind is not installed."""
        mock_which.return_value = None
        analyzer = MemoryAnalyzer()
        assert not analyzer.is_available()
        
        result = analyzer.analyze("./some_binary")
        assert result.error is not None
        assert "not installed" in result.error.lower()
    
    def test_parse_valgrind_output(self):
        """Test parsing Valgrind output."""
        analyzer = MemoryAnalyzer()
        
        sample_output = """
==12345== HEAP SUMMARY:
==12345==     in use at exit: 100 bytes in 2 blocks
==12345==   total heap usage: 10 allocs, 8 frees, 1,000 bytes allocated
==12345== 
==12345== 50 bytes in 1 blocks are definitely lost in loss record 1 of 2
==12345==    at 0x1234: malloc (vg_replace_malloc.c:123)
==12345==    by 0x5678: main (test.cpp:10)
==12345== 
==12345== LEAK SUMMARY:
==12345==    definitely lost: 50 bytes in 1 blocks
==12345==    indirectly lost: 10 bytes in 1 blocks
==12345==      possibly lost: 5 bytes in 0 blocks
==12345==    still reachable: 35 bytes in 0 blocks
==12345==         suppressed: 0 bytes in 0 blocks
"""
        
        result = analyzer._parse_output("./test_binary", sample_output)
        
        assert result.definitely_lost_bytes == 50
        assert result.indirectly_lost_bytes == 10
        assert result.possibly_lost_bytes == 5
        assert result.still_reachable_bytes == 35


class TestCPUAnalyzer:
    """Test CPUAnalyzer class."""
    
    def test_init(self):
        """Test analyzer initialization."""
        analyzer = CPUAnalyzer()
        assert hasattr(analyzer, "_perf_path")
        assert hasattr(analyzer, "_flamegraph_script")
    
    def test_analyze_nonexistent_binary(self):
        """Test analyzing a non-existent binary."""
        analyzer = CPUAnalyzer()
        result = analyzer.analyze("/nonexistent/binary")
        assert result.error is not None
    
    @patch("shutil.which")
    def test_perf_not_installed(self, mock_which):
        """Test behavior when perf is not installed."""
        mock_which.return_value = None
        analyzer = CPUAnalyzer()
        assert not analyzer.is_available()

class TestCacheAnalyzer:
    """Test CacheAnalyzer class."""
    
    def test_init(self):
        analyzer = CacheAnalyzer()
        assert hasattr(analyzer, "_perf_path")

    def test_analyze_nonexistent_binary(self):
        analyzer = CacheAnalyzer()
        result = analyzer.analyze("/nonexistent/binary")
        assert result.error is not None

    @patch("shutil.which")
    def test_perf_not_installed(self, mock_which):
        mock_which.return_value = None
        analyzer = CacheAnalyzer()
        assert not analyzer.is_available()


class TestSyscallAnalyzer:
    """Test SyscallAnalyzer class."""
    
    def test_init(self):
        analyzer = SyscallAnalyzer()
        assert hasattr(analyzer, "_strace_path")

    def test_analyze_nonexistent_binary(self):
        analyzer = SyscallAnalyzer()
        result = analyzer.analyze("/nonexistent/binary")
        assert result.error is not None

    @patch("shutil.which")
    def test_strace_not_installed(self, mock_which):
        mock_which.return_value = None
        analyzer = SyscallAnalyzer()
        assert not analyzer.is_available()


class TestThreadAnalyzer:
    """Test ThreadAnalyzer class."""
    
    def test_init(self):
        analyzer = ThreadAnalyzer()
        assert hasattr(analyzer, "_valgrind_path")

    def test_analyze_nonexistent_binary(self):
        analyzer = ThreadAnalyzer()
        result = analyzer.analyze("/nonexistent/binary")
        assert result.error is not None

    @patch("shutil.which")
    def test_valgrind_not_installed(self, mock_which):
        mock_which.return_value = None
        analyzer = ThreadAnalyzer()
        assert not analyzer.is_available()

