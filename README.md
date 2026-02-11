# Ghost Scan

**Ghost Scan** is a high-performance network reconnaissance tool designed for speed and accuracy. It features a dual-engine architecture, utilizing Python for rapid prototyping and flexibility, and a Rust core for high-concurrency performance.

> **Disclaimer**: This tool is for educational purposes and authorized security testing only. Scanning networks without permission is illegal.

## Features

- **High Performance**:
  - **Rust Engine**: Uses `tokio` for asynchronous I/O, capable of handling thousands of concurrent connections.
  - **Socket Engine**: A pure Python fallback for environments where the Rust library cannot be loaded.
- **Smart Target Parsing**: Supports single IPs, hostnames, and CIDR notation (e.g., `192.168.1.0/24`).
- **Service Fingerprinting**: Automatically grabs banners to identify running services and versions.
- **Port Ranges**: Flexible port specification (e.g., `80`, `1-1000`, `22,443`).
- **Optimization**:
  - Automatically detects local networks and lowers timeouts for faster scanning.
  - Multi-threaded architecture.

## Prerequisites

- **Python**: 3.8+
- **Rust**: Latest stable release (required to build the core engine)

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/iTsSilver321/Ghost-Scan.git
cd Ghost-Scan
```

### 2. Build the Rust Core

To utilize the high-performance Rust engine, you must compile the shared library:

```bash
cd ghost_core
cargo build --release
cd ..
```

This will create `ghost_core.dll` (Windows), `libghost_core.so` (Linux), or `libghost_core.dylib` (macOS) in `ghost_core/target/release/`. The Python script automatically looks for the library in this location.

### 3. Install Python Dependencies

(If `requirements.txt` exists, otherwise standard library is mostly used, check `ghost_scan.py` imports)
This project uses standard Python libraries + `engines` and `utils` packages included in the repo.

## Usage

Basic scan of a local network for common ports:

```bash
python ghost_scan.py 192.168.1.0/24
```

Specify ports and threads:

```bash
python ghost_scan.py 10.10.10.5 --ports 1-65535 --threads 5000
```

Force usage of the Python socket engine:

```bash
python ghost_scan.py google.com --engine socket
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `target` | IP, Hostname, or CIDR (e.g. `192.168.1.1/24`) | Required |
| `-p`, `--ports` | Ports to scan (e.g., `80`, `1-1000`) | `1-1000` |
| `-t`, `--threads` | Number of concurrent threads/tasks | `2000` |
| `--timeout` | Socket timeout in seconds | `1.0` |
| `-e`, `--engine` | Scanning engine (`rust` or `socket`) | `rust` |

## Project Structure

- `ghost_scan.py`: Main entry point.
- `ghost_core/`: Rust source code for the high-performance engine.
- `engines/`:
  - `rust_engine.py`: Python wrapper for the Rust DLL.
  - `socket_engine.py`: Pure Python implementation.
- `analyzers/`: Service fingerprinting logic.
- `utils/`: UI and helper functions.

## License

[MIT License](LICENSE)
