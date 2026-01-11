# 🔍 Perf-Lens

**An intelligent CLI wrapper for C++ performance analysis on Linux.**

Perf-Lens simplifies complex Linux analysis tools (`valgrind`, `perf`) through a user-friendly Python interface with one-click analysis and beautiful visualized reports.

## ✨ Features

- **Memory Leak Detection** — Wraps Valgrind to detect and report Top 10 memory leaks
- **CPU Profiling** — Uses `perf` for sampling-based profiling with hotspot analysis
- **Flame Graph Generation** — Automatically generates interactive SVG flame graphs
- **Beautiful Output** — Rich terminal UI with tables, colors, and progress indicators

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/sweeter-byte/awesome-tool.git
cd awesome-tool/perf_lens

# Install in development mode
pip install -e .

# Or install with dev dependencies
pip install -e ".[dev]"
```

### System Dependencies

```bash
# Install required tools
sudo apt install valgrind linux-tools-common linux-tools-generic

# Optional: Install FlameGraph for CPU flame graphs
git clone https://github.com/brendangregg/FlameGraph ~/FlameGraph
```

## 🚀 Usage

### Check Dependencies

```bash
perf-lens check
```

### Memory Leak Analysis

```bash
# Basic usage
perf-lens analyze memory ./my_program

# With arguments
perf-lens analyze memory ./my_program -a arg1 -a arg2

# With custom timeout
perf-lens analyze memory ./my_program --timeout 600
```

### CPU Profiling

```bash
# Basic usage (30 seconds)
perf-lens analyze cpu ./my_program

# Custom duration
perf-lens analyze cpu ./my_program --duration 60

# Custom output directory
perf-lens analyze cpu ./my_program -o ./reports
```

### Advanced Analysis

#### Cache Performance
```bash
perf-lens analyze cache ./my_program
```

#### System Call Overhead
```bash
perf-lens analyze syscall ./my_program
```

#### Threading Issues
```bash
perf-lens analyze thread ./my_program
```
```

## 📋 Command Reference

```
perf-lens --help                    Show help message
perf-lens --version                 Show version
perf-lens check                     Check system dependencies
perf-lens analyze memory <binary>   Run memory leak analysis
perf-lens analyze cpu <binary>      Run CPU profiling
perf-lens analyze cache <binary>    Run cache performance analysis
perf-lens analyze syscall <binary>  Run system call overhead analysis
perf-lens analyze thread <binary>   Run threading issue detection
```

## 🛠️ Development

```bash
# Run tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=perf_lens
```

## 📄 License

MIT License
