# Cox Killer

**Network evidence dashboard that continuously monitors your connection and proves whether Cox (or any ISP) or your router is the problem.**

Cox Killer runs a ping-based probe against your router gateway and two public DNS servers (Cloudflare 1.1.1.1, Google 8.8.8.8). If the gateway is clean but external targets show loss, the problem is your ISP. If the gateway itself drops packets, it's your local network. The dashboard visualizes this in real time and generates an escalation toolkit with call scripts, counter-arguments, and evidence you can present to support.

![Dashboard](https://img.shields.io/badge/status-active-brightgreen) ![Platform](https://img.shields.io/badge/platform-macOS-lightgrey)

## Features

- **Real-time latency and packet loss charts** for router, Cloudflare, and Google DNS
- **Automated verdict** — immediately tells you who's at fault with supporting evidence
- **Cox call script** — opening statement, counter-arguments for every deflection tactic, magic phrases, escalation ladder through FCC complaint
- **TP-Link BE10000 router integration** — reads/writes router settings via encrypted API, applies recommended optimizations automatically
- **Settings pane** — password management via macOS Keychain, live router stats, CSV/JSON data export
- **Incident log** — tracks every drop and latency spike with timestamps
- **Terminal dashboard** — interactive CLI with sparkline graphs (no browser needed)
- **Report generation** — text reports with diagnosis, suitable for attaching to support tickets
- **Native macOS app** — optional Swift wrapper that manages the daemon and dashboard as a menu bar app

## Requirements

- **macOS** 12.0+ (uses macOS Keychain for password storage, `ping`, `route`)
- **Python 3** (stdlib only, no pip packages)
- **Node.js** 18+ (stdlib only, no npm packages — uses built-in `crypto` and `http`)
- **Bash** 4+ (ships with Homebrew on macOS: `/opt/homebrew/bin/bash`)

Optional:
- `mtr` for traceroute analysis (`brew install mtr`)

## Quick Start

```bash
# Clone
git clone https://github.com/mejohnc-ft/CoxKiller.git
cd CoxKiller

# Start monitoring + web dashboard
./netprobe --web
```

This starts the background probe daemon and opens the dashboard at `http://localhost:8457`.

### Other modes

```bash
# Interactive terminal dashboard (5 min default)
./netprobe

# Terminal dashboard for 30 minutes
./netprobe --duration 30

# Daemon only (background, continuous logging)
./netprobe --daemon

# Web dashboard only (starts daemon if needed)
./netprobe --web

# Stop everything
./netprobe --stop

# Generate report from latest log
./netprobe --report

# MTR traceroute (requires sudo + mtr)
./netprobe --mtr
```

## Router Integration (TP-Link BE10000 / Archer BE800)

The router tools communicate with TP-Link routers via their encrypted LuCI API (AES-128-CBC + RSA).

```bash
# Read current settings and get optimization recommendations
node router_login.mjs <router-password> read

# Auto-apply all recommended optimizations
node router_login.mjs <router-password> apply

# Get router status (WAN IP, uptime, wireless bands, device info)
node router_login.mjs <router-password> status

# Read a specific setting
node router_login.mjs <router-password> get wireless_5g

# Write a specific setting
node router_login.mjs <router-password> set wireless_5g htmode=80
```

You can also store your router password in the macOS Keychain via the dashboard's Settings pane (gear icon in the header), which enables one-click router status checks and connection tests from the GUI.

## How It Works

```
netprobe (bash)          server.py (python)         browser
   |                          |                        |
   |-- ping gateway --------> |                        |
   |-- ping 1.1.1.1 -------> |                        |
   |-- ping 8.8.8.8 -------> |                        |
   |                          |                        |
   +-> logs/*.csv ----------> reads CSV, computes      |
                              stats, analysis,   ----> real-time charts,
                              remediation              verdict, call scripts
```

- **`netprobe`** — bash daemon that pings 3 targets every 5 seconds, logs to CSV
- **`server.py`** — Python HTTP server on port 8457, reads CSVs, serves a single-page dashboard with full analysis engine
- **`router_login.mjs`** — Node.js client for TP-Link encrypted router API
- **`router_ctl.py`** — alternative Python implementation of the router API
- **`CoxKiller.swift`** — native macOS app wrapper (optional)

## Project Structure

```
CoxKiller/
  netprobe            # Network probe daemon (bash)
  server.py           # Web dashboard + API server (python)
  router_login.mjs    # TP-Link router API client (node)
  router_ctl.py       # Router API client alt (python)
  CoxKiller.swift     # Native macOS app wrapper
  make_icon.py        # App icon generator
  cox_killer_icon.png # Favicon / app icon
  logs/               # CSV data, reports, PID files (gitignored)
```

## Platform Support

Cox Killer is currently **macOS only**. The core monitoring (`netprobe` + `server.py`) could work on Linux with minor changes (Keychain calls would need a fallback), but this hasn't been tested yet.

## License

MIT
