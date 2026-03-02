#!/usr/bin/env python3
"""
NotMyRouter - Cross-platform network probe daemon
Pings gateway + Cloudflare + Google DNS, logs to CSV.
Works on macOS, Linux, and Windows.

Usage:
  python3 netprobe.py                  # Run daemon (foreground)
  python3 netprobe.py --daemon         # Run in background
  python3 netprobe.py --stop           # Stop background daemon
  python3 netprobe.py --web            # Start daemon + web dashboard
  python3 netprobe.py --report         # Report from latest log
  python3 netprobe.py --help           # Show help
"""

import subprocess
import sys
import os
import re
import time
import signal
import platform
from datetime import datetime
from pathlib import Path

LOG_DIR = Path.home() / "network-monitor" / "logs"
PID_FILE = LOG_DIR / ".netprobe.pid"
INTERVAL = 5  # seconds between probe cycles
SYSTEM = platform.system()  # 'Darwin', 'Linux', 'Windows'


def detect_gateway():
    """Detect the default gateway IP address."""
    try:
        if SYSTEM == "Darwin":
            out = subprocess.run(
                ["route", "-n", "get", "default"],
                capture_output=True, text=True, timeout=5
            )
            for line in out.stdout.splitlines():
                if "gateway:" in line:
                    return line.split("gateway:")[-1].strip()
        elif SYSTEM == "Linux":
            out = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True, text=True, timeout=5
            )
            parts = out.stdout.split()
            if "via" in parts:
                return parts[parts.index("via") + 1]
        elif SYSTEM == "Windows":
            out = subprocess.run(
                ["powershell", "-Command",
                 "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Select-Object -First 1).NextHop"],
                capture_output=True, text=True, timeout=10
            )
            gw = out.stdout.strip()
            if gw:
                return gw
    except Exception:
        pass
    # Fallback: common gateway addresses
    for candidate in ["192.168.0.1", "192.168.1.1", "10.0.0.1"]:
        lat, loss = do_ping(candidate)
        if loss == 0:
            return candidate
    return "192.168.0.1"


def do_ping(target):
    """Ping a target once, return (latency_ms, loss).
    loss = 0 for success, 100 for failure. latency_ms = 0.0 on failure."""
    try:
        if SYSTEM == "Windows":
            cmd = ["ping", "-n", "1", "-w", "2000", target]
        else:
            cmd = ["ping", "-c", "1", "-W", "2", target]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)

        if result.returncode != 0:
            return 0.0, 100

        output = result.stdout

        # macOS: round-trip min/avg/max/stddev = 4.741/4.741/4.741/0.000 ms
        m = re.search(r"round-trip\s+min/avg/max/\S+\s*=\s*[\d.]+/([\d.]+)/", output)
        if m:
            return float(m.group(1)), 0

        # Linux: rtt min/avg/max/mdev = 4.741/4.741/4.741/0.000 ms
        m = re.search(r"rtt\s+min/avg/max/\S+\s*=\s*[\d.]+/([\d.]+)/", output)
        if m:
            return float(m.group(1)), 0

        # Windows: Average = 4ms  OR  time=4ms or time<1ms
        m = re.search(r"Average\s*=\s*(\d+)\s*ms", output)
        if m:
            return float(m.group(1)), 0

        # Fallback: time=X.Xms or time=Xms
        m = re.search(r"time[=<]([\d.]+)\s*ms", output)
        if m:
            return float(m.group(1)), 0

        # Got a response but couldn't parse latency
        return 0.0, 0

    except (subprocess.TimeoutExpired, Exception):
        return 0.0, 100


def probe_cycle(targets, logfile):
    """Run one probe cycle against all targets, append to CSV."""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    for ip, name in targets:
        lat, loss = do_ping(ip)
        with open(logfile, "a") as f:
            f.write(f"{ts},{ip},{name},{lat:.3f},{loss}\n")


def run_foreground(targets):
    """Run probe loop in the foreground."""
    logfile = LOG_DIR / f"daemon_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    with open(logfile, "w") as f:
        f.write("timestamp,target,target_name,latency_ms,packet_loss\n")

    PID_FILE.write_text(str(os.getpid()))
    print(f"NotMyRouter probe running (PID {os.getpid()})")
    print(f"Targets: {', '.join(f'{name} ({ip})' for ip, name in targets)}")
    print(f"Log: {logfile}")
    print("Press Ctrl+C to stop\n")

    def cleanup(sig, frame):
        PID_FILE.unlink(missing_ok=True)
        print(f"\nStopped. Log: {logfile}")
        generate_report(logfile)
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    cycle = 0
    while True:
        probe_cycle(targets, logfile)
        cycle += 1
        if cycle % 12 == 0:  # every ~60 seconds
            total = cycle * len(targets)
            print(f"  [{datetime.now().strftime('%H:%M:%S')}] {total} probes logged")
        time.sleep(INTERVAL)


def run_daemon(targets):
    """Start probe loop as a background process."""
    if PID_FILE.exists():
        try:
            old_pid = int(PID_FILE.read_text().strip())
            os.kill(old_pid, 0)
            print(f"Daemon already running (PID {old_pid}). Use --stop first.")
            sys.exit(1)
        except (ProcessLookupError, ValueError):
            PID_FILE.unlink(missing_ok=True)

    if SYSTEM == "Windows":
        # Windows: use START /B or pythonw
        script = str(Path(__file__).resolve())
        subprocess.Popen(
            [sys.executable, script, "--foreground"],
            creationflags=subprocess.CREATE_NO_WINDOW,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        # Give it a moment to write the PID file
        time.sleep(1)
        if PID_FILE.exists():
            print(f"Daemon started (PID {PID_FILE.read_text().strip()})")
        else:
            print("Daemon started in background")
    else:
        # Unix: fork
        pid = os.fork()
        if pid > 0:
            # Parent
            time.sleep(0.5)
            print(f"Daemon started (PID {pid})")
            print("Use 'python3 netprobe.py --stop' to stop")
            return
        else:
            # Child — detach
            os.setsid()
            sys.stdout = open(os.devnull, "w")
            sys.stderr = open(os.devnull, "w")
            run_foreground(targets)


def stop_daemon():
    """Stop the background daemon."""
    if not PID_FILE.exists():
        print("No daemon running.")
        return
    try:
        pid = int(PID_FILE.read_text().strip())
        if SYSTEM == "Windows":
            subprocess.run(["taskkill", "/F", "/PID", str(pid)],
                           capture_output=True, timeout=5)
        else:
            os.kill(pid, signal.SIGTERM)
        PID_FILE.unlink(missing_ok=True)
        print(f"Daemon stopped (PID {pid}).")
    except (ProcessLookupError, ValueError):
        PID_FILE.unlink(missing_ok=True)
        print("Daemon was not running (stale PID file removed).")


def run_web(targets):
    """Start daemon + web dashboard."""
    web_pid_file = LOG_DIR / ".webdashboard.pid"

    # Check if dashboard already running
    if web_pid_file.exists():
        try:
            pid = int(web_pid_file.read_text().strip())
            os.kill(pid, 0)
            print(f"Dashboard already running (PID {pid})")
            open_browser()
            return
        except (ProcessLookupError, ValueError):
            web_pid_file.unlink(missing_ok=True)

    # Start daemon if not running
    if not PID_FILE.exists():
        run_daemon(targets)
    else:
        try:
            pid = int(PID_FILE.read_text().strip())
            os.kill(pid, 0)
        except (ProcessLookupError, ValueError):
            run_daemon(targets)

    # Start web server
    server_script = Path(__file__).parent / "server.py"
    print("Starting NotMyRouter dashboard on http://localhost:8457 ...")

    if SYSTEM == "Windows":
        proc = subprocess.Popen(
            [sys.executable, str(server_script)],
            creationflags=subprocess.CREATE_NO_WINDOW,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
    else:
        proc = subprocess.Popen(
            [sys.executable, str(server_script)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )

    web_pid_file.write_text(str(proc.pid))
    time.sleep(1)

    if proc.poll() is None:
        print(f"Dashboard running (PID {proc.pid})")
        open_browser()
    else:
        print("Failed to start dashboard.")
        web_pid_file.unlink(missing_ok=True)


def open_browser():
    """Open the dashboard URL in the default browser."""
    import webbrowser
    webbrowser.open("http://localhost:8457")


def generate_report(logfile=None):
    """Generate a report from a CSV log file."""
    if logfile is None:
        logs = sorted(LOG_DIR.glob("*.csv"), key=lambda f: f.stat().st_mtime, reverse=True)
        logfile = next((f for f in logs if f.stat().st_size > 50), None)
    if not logfile or not Path(logfile).exists():
        print("No log file found.")
        return

    logfile = Path(logfile)
    lines = logfile.read_text().strip().splitlines()
    if len(lines) < 2:
        print("Log file is empty.")
        return

    # Parse CSV
    from collections import defaultdict
    targets = defaultdict(lambda: {"total": 0, "lost": 0, "latencies": []})

    for line in lines[1:]:
        parts = line.split(",")
        if len(parts) < 5:
            continue
        ip, name = parts[1], parts[2]
        try:
            lat, loss = float(parts[3]), int(parts[4])
        except ValueError:
            continue
        t = targets[f"{name} ({ip})"]
        t["total"] += 1
        if loss == 100:
            t["lost"] += 1
        elif lat > 0:
            t["latencies"].append(lat)

    first_ts = lines[1].split(",")[0]
    last_ts = lines[-1].split(",")[0]
    total_probes = len(lines) - 1

    report_file = logfile.with_suffix(".txt").with_name(logfile.stem + "_REPORT.txt")

    report = []
    report.append("=" * 46)
    report.append("  NETWORK MONITORING REPORT")
    report.append("=" * 46)
    report.append(f"Period: {first_ts}  ->  {last_ts}")
    report.append(f"Total probes: {total_probes}")
    report.append("")

    for key, t in targets.items():
        loss_pct = round((t["lost"] / t["total"]) * 100, 1) if t["total"] else 0
        lats = t["latencies"]
        avg_lat = round(sum(lats) / len(lats), 1) if lats else 0
        max_lat = round(max(lats), 1) if lats else 0
        jitter = 0
        if len(lats) > 1:
            diffs = [abs(lats[i] - lats[i - 1]) for i in range(1, len(lats))]
            jitter = round(sum(diffs) / len(diffs), 1)

        report.append(f"--- {key} ---")
        report.append(f"  Probes:       {t['total']}")
        report.append(f"  Packet Loss:  {loss_pct}% ({t['lost']} lost)")
        report.append(f"  Avg Latency:  {avg_lat} ms")
        report.append(f"  Max Latency:  {max_lat} ms")
        report.append(f"  Avg Jitter:   {jitter} ms")
        report.append("")

    report.append("=" * 46)
    report.append(f"  Log file: {logfile}")
    report.append(f"  Generated: {datetime.now()}")
    report.append("=" * 46)

    text = "\n".join(report)
    report_file.write_text(text)
    print(text)
    print(f"\nReport saved to: {report_file}")


def main():
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    gateway = detect_gateway()
    targets = [
        (gateway, "Router/Gateway"),
        ("1.1.1.1", "Cloudflare DNS"),
        ("8.8.8.8", "Google DNS"),
    ]

    args = sys.argv[1:]
    cmd = args[0] if args else "--foreground"

    if cmd in ("--help", "-h"):
        print(__doc__)
        print(f"Detected gateway: {gateway}")
        print(f"Platform: {SYSTEM}")
    elif cmd == "--daemon":
        run_daemon(targets)
    elif cmd == "--foreground":
        run_foreground(targets)
    elif cmd == "--stop":
        stop_daemon()
    elif cmd == "--web":
        run_web(targets)
    elif cmd == "--report":
        generate_report(args[1] if len(args) > 1 else None)
    else:
        print(f"Unknown command: {cmd}")
        print("Use --help for usage.")
        sys.exit(1)


if __name__ == "__main__":
    main()
