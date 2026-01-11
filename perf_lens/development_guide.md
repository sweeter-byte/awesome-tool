# Perf-Lens Development Guide

## 1. Project Overview
**Name**: perf-lens
**Goal**: An intelligent CLI wrapper for C++ performance analysis on Linux.
**Core Philosophy**: Simplify the usage of complex Linux analysis tools (`perf`, `valgrind`, etc.) through a user-friendly Python interface, offering one-click analysis and visualized reports.

## 2. Technology Stack
- **Language**: Python 3.10+
- **CLI Framework**: `Click` (or `Typer`) for robust command-line argument parsing.
- **Terminal UI**: `Rich` for beautiful output.
- **Core Tools**: `valgrind`, `perf`, `flamegraph.pl`.

## 3. Project Structure
```text
awesome-tool/           # Repository Root
└── perf_lens/          # This Project Package
    ├── perf_lens/      # Source Code
    │   ├── __init__.py
    │   ├── cli.py      # Entry point
    │   ├── analyzers/  # Analysis Logic
    │   └── reporters/  # Report Generation
    ├── tests/
    ├── pyproject.toml
    └── README.md
```

## 4. Planned Features

### 4.1 Memory Leak Analysis
- **Command**: `perf-lens analyze memory ./target_bin`
- **Output**: Top 10 Leaks.

### 4.2 CPU & Flame Graph
- **Command**: `perf-lens analyze cpu ./target_bin`
- **Output**: SVG Flame Graph + Hotspot Summary.

### 4.3 Advanced Analysis
- **Cache**: Miss Rates (L1/L3).
- **System**: Syscall overhead.
- **Threading**: Deadlocks.

## 5. Development Workflow
1.  **Setup**: `pip install -e .`
2.  **Run**: `python -m perf_lens.cli --help`
3.  **Test**: `pytest tests/`
