# pypn

A small Python toolkit that downloads OpenVPN configurations from VPNGate, launches multiple OpenVPN connections concurrently, and runs a SOCKS5 proxy bound to each connection's TUN interface. The goal is to create multiple local SOCKS5 proxies mapped to different VPN connections, benchmark latency, and replace unstable connections automatically.

## Key features
- Download and decode `.ovpn` files from VPNGate.
- Launch multiple OpenVPN processes in parallel.
- Start a SOCKS5 server (`socks5_proxy.py`) for each VPN connection (each `tunX`).
- Benchmark latency using `requests` (to `http://www.google.com`) and verify public IP via `https://icanhazip.com`.
- Lifecycle management: start, stop and replace connections with high latency or high fail rates.

## Requirements
- OS: Linux (run as root). Some parts may work on macOS; Windows is not recommended because the project checks `os.getuid()`.
- Python 3.8+
- Python packages: `requests`, `psutil`
- `openvpn` must be installed and available in `PATH`.

Example install (Debian/Ubuntu):

```bash
sudo apt update
sudo apt install -y openvpn python3-pip
pip3 install requests psutil
```

## Configuration
- `up.txt`: stores OpenVPN auth (username on first line, password on second). The repository includes a sample `up.txt`.
- VPN configs are saved into `./configs` by `utils.load_config()`.
- Main runtime parameters are in `main.py`:
  - `NUM_PROXY` / `PROXY_PORTS`: number of proxies and the port range (default: 10 ports starting at 1080).
  - `MAX_THREADS`: threadpool size used for parallel tasks.

## Usage
Run the manager as root:

```bash
sudo python3 main.py
```

Check logs in `vpn_manager.log`.

To test an individual proxy (e.g. port 1080) use:

```bash
python3 test.py
```

## Files overview
- `main.py`: entrypoint — checks root, manages proxy ports and running VPN connections, benchmarks and replaces bad connections.
- `utils.py`: helper functions — fetch VPN list from VPNGate, decode and save `.ovpn` files, benchmark latency via proxies, and initialize VPNConnection instances.
- `vpn.py`: `VPNConnection` class — starts the `openvpn` process, monitors output to detect `tunX`, and starts `socks5_proxy.py` bound to that interface and port.
- `socks5_proxy.py`: a small SOCKS5 server (based on an open source example). It can bind outgoing traffic to a specific interface using `SO_BINDTODEVICE` (requires root).
- `test.py`: a simple script to test a local SOCKS5 proxy.
- `up.txt`: sample username/password file used by `openvpn`.

## How it works (summary)
1. `main.py` tracks which proxy ports are in use.
2. `utils.load_config()` downloads VPNGate entries, decodes base64 `ovpn` content and stores `.ovpn` files in `./configs`.
3. `utils.load_configs()` starts a set of `VPNConnection` instances (each runs `openvpn`).
4. When `openvpn` outputs `Initialization Sequence Completed`, `VPNConnection` launches `socks5_proxy.py` with `--interface tunX` and an assigned port.
5. `utils.benchmark_vpn_latency()` measures latency and obtains the public IP through the proxy to filter poor connections.
6. `main.py` continuously monitors and replaces connections with latency or fail-rate beyond thresholds.

## Security & operational notes
- Must run as `root` to bind outgoing sockets to specific interfaces (`SO_BINDTODEVICE`) and to create TUN devices.
- `up.txt` contains plain-text credentials — protect this file (e.g., `chmod 600 up.txt`).
- Running many OpenVPN connections consumes bandwidth and system resources (file descriptors, CPU). Tune `NUM_PROXY` and `MAX_THREADS` accordingly.

## Troubleshooting
- `os.getuid()` errors on Windows: run on Linux.
- `openvpn` command not found: install OpenVPN and ensure it is in `PATH`.
- Proxy not changing IPs: check `vpn_manager.log`, OpenVPN logs, `up.txt`, and `.ovpn` files in `./configs`.

## Quick customization
- Change the number of proxies: edit `NUM_PROXY` in `main.py`.
- Change port range: edit `PROXY_PORTS` in `main.py`.
- Adjust proxy server defaults by changing `socks5_proxy.py` CLI arguments when started in `vpn.py`.

## Final notes
This repository is intended as an experimental tool to create multiple local SOCKS5 proxies routed through multiple OpenVPN connections fetched from VPNGate. Do not use in production without assessing security, performance, and legal implications.