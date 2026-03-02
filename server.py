#!/usr/bin/env python3
"""
NotMyRouter - Network evidence dashboard
Continuously monitors and proves whether Cox or your router is the problem.
Run: python3 ~/network-monitor/server.py
Then open: http://localhost:8457
"""

import http.server
import json
import csv
import os
import signal
import sys
import math
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict
import subprocess
import platform
PORT = 8457
LOG_DIR = Path.home() / "network-monitor" / "logs"
PID_FILE = LOG_DIR / ".webdashboard.pid"
CRED_FILE = Path.home() / "network-monitor" / ".credentials"
IS_MACOS = platform.system() == "Darwin"


# === Cross-platform password storage ===
# macOS: uses Keychain via `security` CLI (encrypted by the OS)
# Other: plaintext file with 0600 permissions. This is the same approach
# used by ~/.netrc, ~/.pgpass, and similar tools. The file is gitignored.
# If you need stronger protection, use an environment variable instead:
#   export ROUTER_PASSWORD=yourpassword

def store_password(password):
    """Store router password. Returns (success, error_msg)."""
    if IS_MACOS:
        try:
            subprocess.run(
                ["security", "add-generic-password", "-a", "NotMyRouter",
                 "-s", "router-password", "-w", password, "-U"],
                capture_output=True, text=True, timeout=5, check=True
            )
            return True, None
        except subprocess.CalledProcessError as e:
            return False, e.stderr.strip() or "Keychain error"
        except Exception as e:
            return False, str(e)
    else:
        try:
            CRED_FILE.write_text(password)
            try:
                CRED_FILE.chmod(0o600)
            except OSError:
                pass  # Windows doesn't support Unix permissions
            return True, None
        except Exception as e:
            return False, str(e)

def retrieve_password():
    """Retrieve stored router password. Returns password string or None.
    Checks environment variable first, then platform credential store."""
    env_pw = os.environ.get("ROUTER_PASSWORD")
    if env_pw:
        return env_pw
    if IS_MACOS:
        try:
            result = subprocess.run(
                ["security", "find-generic-password", "-a", "NotMyRouter",
                 "-s", "router-password", "-w"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass
        return None
    else:
        try:
            if not CRED_FILE.exists():
                return None
            return CRED_FILE.read_text().strip()
        except Exception:
            return None

def password_is_stored():
    """Check if a password is stored."""
    if IS_MACOS:
        try:
            result = subprocess.run(
                ["security", "find-generic-password", "-a", "NotMyRouter",
                 "-s", "router-password", "-w"],
                capture_output=True, text=True, timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False
    else:
        return CRED_FILE.exists()


def get_all_logs():
    """Get all CSV log files, newest first."""
    return sorted(LOG_DIR.glob("*.csv"), key=lambda f: f.stat().st_mtime, reverse=True)


def get_latest_log():
    """Find the most recent CSV with data."""
    for f in get_all_logs():
        if f.stat().st_size > 50:
            return f
    return None


def moving_average(values, window):
    """Compute moving average, returning same-length list."""
    if len(values) < window:
        return values[:]
    result = []
    for i in range(len(values)):
        start = max(0, i - window + 1)
        chunk = [v for v in values[start:i+1] if v is not None]
        result.append(round(sum(chunk) / len(chunk), 1) if chunk else 0)
    return result


def percentile(sorted_vals, pct):
    if not sorted_vals:
        return 0
    idx = int(len(sorted_vals) * pct / 100)
    return round(sorted_vals[min(idx, len(sorted_vals) - 1)], 1)


def detect_incidents(timestamps, latencies, losses, name, threshold_ms=100):
    """Group consecutive bad samples into incident windows."""
    incidents = []
    current = None

    for i in range(len(timestamps)):
        is_bad = losses[i] == 100 or (latencies[i] and latencies[i] > threshold_ms)
        if is_bad:
            if current is None:
                current = {
                    "start": timestamps[i], "end": timestamps[i],
                    "target": name, "drops": 0, "spikes": 0,
                    "max_lat": 0, "samples": 0
                }
            current["end"] = timestamps[i]
            current["samples"] += 1
            if losses[i] == 100:
                current["drops"] += 1
            else:
                current["spikes"] += 1
                current["max_lat"] = max(current["max_lat"], latencies[i])
        else:
            if current is not None:
                incidents.append(current)
                current = None
    if current is not None:
        incidents.append(current)
    return incidents


def build_analysis(targets_data):
    """Generate plain-English analysis findings."""
    findings = []
    router = None
    internet_targets = []

    for t in targets_data:
        if "192.168" in t["ip"] or "10.0" in t["ip"]:
            router = t
        else:
            internet_targets.append(t)

    if not router or not internet_targets:
        return [{"severity": "info", "title": "Insufficient data", "detail": "Waiting for more probe data to analyze."}]

    total_probes = router["total_probes"]

    # === Finding 1: Who's at fault? ===
    router_loss = router["loss_pct"]
    inet_loss = max(t["loss_pct"] for t in internet_targets)
    inet_avg_loss = sum(t["loss_pct"] for t in internet_targets) / len(internet_targets)

    if router_loss >= 5:
        findings.append({
            "severity": "critical",
            "title": "Your router/Wi-Fi is dropping packets",
            "detail": f"Router packet loss is {router_loss}%. This means packets are dying between your device and your router before they even reach Cox. This is a local network issue."
        })
    elif router_loss < 1 and inet_avg_loss >= 3:
        findings.append({
            "severity": "critical",
            "title": "Cox is dropping your packets",
            "detail": f"Router loss: {router_loss}% (clean). Internet loss: {inet_avg_loss:.1f}% (bad). Your local network is fine - packets are being lost on Cox's network after leaving your router. This is ISP-side packet loss."
        })
    elif router_loss < 1 and inet_avg_loss >= 1:
        findings.append({
            "severity": "warning",
            "title": "Upstream packet loss detected (likely Cox)",
            "detail": f"Router loss: {router_loss}% vs Internet loss: {inet_avg_loss:.1f}%. Your router is clean but there's measurable loss beyond it. More monitoring time will strengthen this evidence."
        })
    elif router_loss < 0.5 and inet_avg_loss < 0.5:
        findings.append({
            "severity": "ok",
            "title": "No significant packet loss",
            "detail": "Both router and internet paths show minimal loss. If you're experiencing issues, they may be intermittent - keep monitoring."
        })

    # === Finding 2: Latency analysis ===
    router_p50 = router.get("p50_latency", 0)
    router_p95 = router["p95_latency"]
    router_avg = router["avg_latency"]

    if router_p50 < 10 and router_p95 > 80:
        findings.append({
            "severity": "warning",
            "title": "Router latency is spiky",
            "detail": f"Median router latency is good ({router_p50}ms) but P95 is {router_p95}ms. This means ~5% of the time your router takes 10x+ longer to respond. This pattern suggests periodic Wi-Fi congestion, interference, or router CPU spikes."
        })
    elif router_avg > 15:
        findings.append({
            "severity": "warning",
            "title": "Router latency is elevated",
            "detail": f"Average router round-trip is {router_avg}ms. A healthy local connection should be under 5ms. This could indicate Wi-Fi signal issues, router overload, or interference."
        })

    # === Finding 3: Jitter analysis ===
    for t in internet_targets:
        if t["jitter"] > 50:
            findings.append({
                "severity": "warning",
                "title": f"High jitter to {t['name']} ({t['jitter']}ms)",
                "detail": f"Latency to {t['name']} varies by an average of {t['jitter']}ms between consecutive probes. This causes buffering in video calls and streaming. Consistent jitter across multiple targets points to ISP-level instability."
            })
            break  # one jitter finding is enough

    # === Finding 4: Correlation check ===
    if len(internet_targets) >= 2:
        losses = [t["loss_pct"] for t in internet_targets]
        if all(l >= 1 for l in losses):
            findings.append({
                "severity": "info",
                "title": "Loss confirmed across multiple endpoints",
                "detail": f"Both {internet_targets[0]['name']} ({internet_targets[0]['loss_pct']}% loss) and {internet_targets[1]['name']} ({internet_targets[1]['loss_pct']}% loss) show loss. Since these are different destinations reached via different paths after Cox's network, this strongly suggests the problem is on Cox's side, not a single remote server."
            })

    # === Finding 5: Data sufficiency ===
    if total_probes < 100:
        findings.append({
            "severity": "info",
            "title": "Still collecting data",
            "detail": f"Only {total_probes} probes so far. For strong evidence to present to Cox, aim for at least 500+ probes (about 45 minutes of daemon monitoring). 24 hours is ideal for showing patterns."
        })
    elif total_probes >= 500:
        duration_mins = total_probes * 5 / 60  # daemon probes every ~5s, 3 targets
        findings.append({
            "severity": "info",
            "title": f"Good sample size ({total_probes} probes)",
            "detail": f"You have enough data for a credible report to Cox support. Screenshot this dashboard during your next call."
        })

    return findings


def build_remediation(targets_data):
    """Generate data-driven remediation for Cox call script and router fixes."""
    router = None
    internet_targets = []
    for t in targets_data:
        if "192.168" in t["ip"] or "10.0" in t["ip"]:
            router = t
        else:
            internet_targets.append(t)

    if not router:
        return {"cox": {}, "router": {}}

    # Compute values for injection into scripts
    r_loss = router["loss_pct"]
    r_p50 = router.get("p50_latency", 0)
    r_p95 = router["p95_latency"]
    r_avg = router["avg_latency"]
    r_jitter = router["jitter"]
    r_probes = router["total_probes"]

    i_loss = max((t["loss_pct"] for t in internet_targets), default=0)
    i_avg_loss = sum(t["loss_pct"] for t in internet_targets) / len(internet_targets) if internet_targets else 0
    i_jitter = max((t["jitter"] for t in internet_targets), default=0)
    i_p95 = max((t["p95_latency"] for t in internet_targets), default=0)
    hours = round(r_probes * 5 / 3600, 1)  # daemon probes ~every 5s, 3 targets per cycle

    # === COX CALL SCRIPT ===
    cox = {}

    cox["opening_script"] = (
        f"I have been continuously monitoring my connection for {hours} hours with {r_probes} probe samples. "
        f"I have {r_loss}% packet loss to my local gateway but {i_avg_loss:.1f}% packet loss and "
        f"{i_jitter}ms of jitter to external targets including Cloudflare and Google DNS. "
        f"This data proves the problem is in your network infrastructure, not my equipment. "
        f"I am connected via Ethernet and my modem is on your certified device list. "
        f"I need someone to check the CMTS logs for my modem and dispatch a maintenance technician "
        f"to check signal levels at the tap."
    )

    cox["counters"] = [
        {
            "their_move": "Reboot your modem",
            "your_response": f"I have already power-cycled the modem. The issue persists across reboots. I have {hours} hours of continuous monitoring data showing a consistent pattern of {i_avg_loss:.1f}% packet loss upstream. I need a signal/line check, not a reboot."
        },
        {
            "their_move": "It's your router or Wi-Fi",
            "your_response": f"My monitoring shows {r_loss}% packet loss to my own router and {i_avg_loss:.1f}% to external targets. If it were my router, I would see loss to the gateway too. The data clearly shows loss begins past my modem on your network."
        },
        {
            "their_move": "Your speeds look fine from our end",
            "your_response": f"Speed tests measure throughput, not packet loss or jitter. I am experiencing {i_avg_loss:.1f}% packet loss and {i_jitter}ms jitter, which are quality-of-service metrics your speed test does not capture. Please check the CMTS logs for T3/T4 timeouts and uncorrectable codeword errors."
        },
        {
            "their_move": "We don't see any outage in your area",
            "your_response": f"This is not an outage. This is degraded performance - {i_avg_loss:.1f}% packet loss and {i_jitter}ms jitter consistent with node congestion or a signal-level issue. Can you check the upstream SNR and power levels on my modem's CMTS port?"
        },
        {
            "their_move": "Try using our modem/router instead",
            "your_response": "My modem is on Cox's certified device list. The issue pattern - clean local network, loss to multiple external targets - matches a plant-side problem. I need a technician to check signal levels at the tap and the drop."
        },
    ]

    cox["escalation_steps"] = [
        {
            "step": "Tier 1 (Phone/Chat)",
            "action": "Call 1-800-234-3993. Present your data, counter their script. Always get a ticket number.",
            "if_blocked": "Say: 'I need this escalated to Tier 2 technical support. Please transfer me.' They are required to do so when you request it."
        },
        {
            "step": "Tier 2 / CAG",
            "action": "Present monitoring data and modem diagnostics. Ask them to check your modem's signal history on CMTS, check port utilization, and verify node congestion flags.",
            "if_blocked": "Request a maintenance technician (not an installer). Ask them to note 'check signal at tap and plant-side issues' in the ticket."
        },
        {
            "step": "Executive Escalation",
            "action": "Email cox.help@cox.com with account number, all ticket numbers, and your monitoring data screenshots. This goes to the executive escalation team.",
            "if_blocked": "Proceed to FCC complaint."
        },
        {
            "step": "FCC Complaint (nuclear option)",
            "action": "File at consumercomplaints.fcc.gov under 'Internet'. Include duration of problem, ticket numbers, and your packet loss/jitter data. Cox must respond in writing within 30 days.",
            "if_blocked": "Your complaint goes to their Executive Escalations department. They typically contact you within 1-2 weeks."
        },
    ]

    cox["magic_phrases"] = [
        "Check the CMTS logs for my modem's MAC address",
        "T3/T4 timeouts in my modem event log",
        "What is the utilization on my CMTS upstream/downstream port?",
        "Signal level check at the tap and the drop",
        "Check my modem's flap list entry",
        "Run a signal history report, not just a point-in-time check",
        "I need a truck roll for a line check, not a modem reboot",
        "Dispatch a maintenance technician, not an installer",
        "Is my node flagged for a planned split?",
        "Escalate to the Field Escalation Team",
    ]

    cox["expected_outcomes"] = [
        {"outcome": "Service credits", "likelihood": "high", "detail": "Ask billing for a credit once documented. Typical 15-100% off your bill for sustained issues. Always ask - they never offer proactively."},
        {"outcome": "Truck roll / line check", "likelihood": "high", "detail": "Standard after Tier 1 fails. Insist on a maintenance tech, not an installer. Free if the issue is on Cox's side."},
        {"outcome": "DOCSIS signal adjustments", "likelihood": "medium", "detail": "Tech can adjust signal at the tap, replace damaged connectors, fix the drop cable, or adjust attenuators. Resolves many signal-quality issues."},
        {"outcome": "CMTS port reassignment", "likelihood": "medium", "detail": "If your CMTS port is noisy or overloaded, maintenance can move your modem to a different port. Less drastic than a node split."},
        {"outcome": "Node split", "likelihood": "low", "detail": "The real fix for congestion but it's a capital project. Cox only does this with enough complaints or FCC pressure. Timeline is months, not weeks."},
        {"outcome": "'No problem found'", "likelihood": "medium", "detail": "The frustrating outcome where a tech measures signal once and closes the ticket. Counter with your continuous monitoring data that captures the intermittent pattern."},
    ]

    # === ROUTER FIXES (TP-Link BE10000 / Archer BE800) ===
    rtr = {}

    rtr["diagnosis"] = []
    if r_p50 < 10 and r_p95 > 80:
        rtr["diagnosis"].append(f"Median latency is healthy ({r_p50}ms) but P95 is {r_p95}ms. This 'spiky' pattern points to periodic Wi-Fi contention, not a baseline problem. The most likely causes are Smart Connect band-hopping, wide channel widths, or MLO scheduling overhead.")
    elif r_avg > 15:
        rtr["diagnosis"].append(f"Average latency to your gateway is {r_avg}ms (should be <5ms). This suggests sustained Wi-Fi congestion, weak signal, or router CPU load.")
    if r_jitter > 20:
        rtr["diagnosis"].append(f"Router jitter is {r_jitter}ms. Healthy Wi-Fi should be <5ms jitter. This means your connection quality is inconsistent even before packets leave your house.")

    rtr["high_impact"] = [
        {
            "setting": "Disable Smart Connect",
            "location": "Advanced > Wireless > Wireless Settings",
            "value": "OFF",
            "why": "Smart Connect causes devices to bounce between 2.4/5/6GHz bands. Users report latency jumping from 9ms to 150ms during band switches. Create separate SSIDs per band and pin latency-sensitive devices to 5GHz or 6GHz.",
            "expected_result": "P95 latency should drop significantly. Band-hopping spikes eliminated."
        },
        {
            "setting": "Disable MLO (Multi-Link Operation)",
            "location": "Advanced > Wireless > MLO Settings",
            "value": "OFF (or 5G+6G only)",
            "why": "Wi-Fi 7 MLO is immature. Known disconnection bugs with Samsung and Apple devices. The router switching traffic between links introduces periodic latency spikes - exactly the pattern you're seeing.",
            "expected_result": "Removes multi-link scheduling overhead. Test for 30 min to see if P95 improves."
        },
        {
            "setting": "Disable QoS",
            "location": "Advanced > QoS",
            "value": "OFF",
            "why": "TP-Link's QoS implementation is confirmed buggy - it CAUSES bufferbloat instead of fixing it. Users report upload latency approaching 1 second with QoS enabled. It is not real SQM (fq_codel/CAKE).",
            "expected_result": "Eliminates artificial latency from broken traffic shaping."
        },
        {
            "setting": "Disable Flow Controller",
            "location": "Advanced > LAN Settings",
            "value": "Uncheck RX Enable and TX Enable on both LAN and WAN",
            "why": "Flow Controller sends PAUSE frames that create micro-bufferbloat. Multiple users confirm this resolves latency spikes that persist even with QoS tuning.",
            "expected_result": "Removes PAUSE frame-induced latency spikes."
        },
        {
            "setting": "Reduce 6GHz channel width",
            "location": "Advanced > Wireless > 6GHz",
            "value": "160 MHz (not 320 MHz)",
            "why": "320MHz doubles your collision domain. In any environment with competing signals, this causes retransmissions that show up as P95 spikes while median stays fine.",
            "expected_result": "Better tail latency. Throughput still excellent at 160MHz."
        },
        {
            "setting": "Reduce 5GHz channel width",
            "location": "Advanced > Wireless > 5GHz",
            "value": "80 MHz",
            "why": "160MHz on 5GHz picks up more interference and has more contention. 80MHz is the best balance of speed and stability.",
            "expected_result": "More consistent latency on the 5GHz band."
        },
        {
            "setting": "Set 5GHz to UNII-1 channel",
            "location": "Advanced > Wireless > 5GHz",
            "value": "Channel 36, 40, 44, or 48 (manual)",
            "why": "Avoids DFS channels that cause periodic channel switches when radar is detected. DFS switches cause brief disconnections that look like packet loss.",
            "expected_result": "Eliminates DFS-related dropouts."
        },
    ]

    rtr["medium_impact"] = [
        {
            "setting": "Disable TWT (Target Wake Time)",
            "location": "Advanced > Wireless > Additional Settings",
            "value": "OFF",
            "why": "TWT negotiates sleep/wake schedules. For always-on devices, waking from TWT sleep introduces latency spikes. Only useful for battery IoT devices.",
            "expected_result": "Removes wake scheduling delays for always-on devices."
        },
        {
            "setting": "Disable OFDMA",
            "location": "Advanced > Wireless > Additional Settings",
            "value": "OFF (if option available)",
            "why": "TP-Link confirmed a bug where OFDMA degrades inter-client performance and can increase latency.",
            "expected_result": "May reduce periodic latency bumps."
        },
        {
            "setting": "Set 2.4GHz to 20MHz width",
            "location": "Advanced > Wireless > 2.4GHz",
            "value": "20 MHz, Channel 1/6/11 (manual, least congested)",
            "why": "Only 3 non-overlapping 2.4GHz channels. Wider channels cause collisions in congested environments.",
            "expected_result": "More stable 2.4GHz for IoT devices."
        },
        {
            "setting": "Use WPA2/WPA3 mixed mode",
            "location": "Advanced > Wireless > Security",
            "value": "WPA2/WPA3",
            "why": "WPA3-only is reported less stable on this router. Mixed mode maintains security while improving compatibility.",
            "expected_result": "Fewer authentication-related disconnections."
        },
        {
            "setting": "Disable SIP ALG",
            "location": "Advanced > NAT Forwarding > ALG",
            "value": "OFF",
            "why": "Known to cause VoIP and latency issues across most consumer routers.",
            "expected_result": "Better VoIP call quality."
        },
    ]

    rtr["firmware"] = {
        "current_recommended": "1.2.3 Build 20250314",
        "stable_fallback": "1.1.6 Build 20240808",
        "note": "1.2.3 is the latest but some users report Wi-Fi speed regressions. 1.1.6 was the major stability milestone that fixed MLO disconnections and improved overall stability. If 1.2.3 causes issues, fall back to 1.1.6.",
        "url": "https://www.tp-link.com/us/support/download/archer-be800/"
    }

    rtr["test_procedure"] = (
        "Change ONE setting at a time, then monitor with NotMyRouter for 30 minutes. "
        "Compare your P95 and jitter before/after. The first change that drops your "
        f"router P95 below 20ms (currently {r_p95}ms) identifies the culprit. "
        "Recommended order: Smart Connect > MLO > QoS+Flow Controller > Channel width > TWT+OFDMA."
    )

    return {"cox": cox, "router": rtr}


def parse_csv_data(filepath, minutes=60):
    """Read CSV and return data with full analysis."""
    if not filepath or not filepath.exists():
        return {"error": "No log file found", "targets": [], "analysis": [], "verdict": "loading", "verdict_text": "No data yet"}

    cutoff = datetime.now() - timedelta(minutes=minutes)
    targets = {}

    # Read all matching log files if the requested window extends beyond the current file
    files_to_read = [filepath]
    if minutes > 120:
        for f in get_all_logs():
            if f != filepath and f.stat().st_size > 50:
                files_to_read.append(f)

    for fpath in files_to_read:
        try:
            with open(fpath, "r") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    try:
                        ts = datetime.strptime(row["timestamp"], "%Y-%m-%d %H:%M:%S")
                        if ts < cutoff:
                            continue
                        target = row["target"]
                        name = row["target_name"]
                        lat = float(row["latency_ms"])
                        loss = int(row["packet_loss"])

                        if target not in targets:
                            targets[target] = {
                                "name": name, "ip": target,
                                "raw_timestamps": [], "raw_latencies": [], "raw_losses": [],
                                "total": 0, "lost": 0, "lat_values": [],
                            }

                        t = targets[target]
                        t["raw_timestamps"].append(ts)
                        t["raw_latencies"].append(round(lat, 1))
                        t["raw_losses"].append(loss)
                        t["total"] += 1
                        if loss == 100:
                            t["lost"] += 1
                        elif lat > 0:
                            t["lat_values"].append(lat)
                    except (ValueError, KeyError):
                        continue
        except Exception:
            continue

    # Sort by timestamp (in case multiple files)
    for t in targets.values():
        if t["raw_timestamps"]:
            combined = sorted(zip(t["raw_timestamps"], t["raw_latencies"], t["raw_losses"]))
            t["raw_timestamps"] = [c[0] for c in combined]
            t["raw_latencies"] = [c[1] for c in combined]
            t["raw_losses"] = [c[2] for c in combined]

    result = {
        "targets": [],
        "log_file": str(filepath),
        "generated": datetime.now().strftime("%H:%M:%S"),
        "window_minutes": minutes,
    }

    order = sorted(targets.keys(), key=lambda k: (0 if "192.168" in k or "10.0" in k else 1, k))

    for ip in order:
        t = targets[ip]
        vals = sorted(t["lat_values"])
        successful = len(vals)
        avg_lat = round(sum(vals) / successful, 1) if successful else 0
        loss_pct = round((t["lost"] / t["total"]) * 100, 1) if t["total"] else 0

        p50 = percentile(vals, 50)
        p95 = percentile(vals, 95)
        p99 = percentile(vals, 99)
        lat_max = round(max(vals), 1) if vals else 0

        jitter = 0
        if len(vals) > 1:
            diffs = [abs(vals[i] - vals[i - 1]) for i in range(1, len(vals))]
            jitter = round(sum(diffs) / len(diffs), 1)

        # Compute jitter from raw (time-ordered) data for accuracy
        raw_lats_clean = [l for l, lo in zip(t["raw_latencies"], t["raw_losses"]) if lo != 100 and l > 0]
        if len(raw_lats_clean) > 1:
            raw_diffs = [abs(raw_lats_clean[i] - raw_lats_clean[i-1]) for i in range(1, len(raw_lats_clean))]
            jitter = round(sum(raw_diffs) / len(raw_diffs), 1)

        # Charts: raw data + moving averages
        # Downsample if too many points
        step = max(1, len(t["raw_timestamps"]) // 500)
        chart_ts = [ts.strftime("%H:%M:%S") for ts in t["raw_timestamps"][::step]]
        chart_lat = t["raw_latencies"][::step]
        chart_loss = t["raw_losses"][::step]

        # Moving average (window of 10 samples)
        ma_window = min(10, max(3, len(chart_lat) // 20))
        chart_ma = moving_average(chart_lat, ma_window)

        # Detect incidents
        all_ts_str = [ts.strftime("%H:%M:%S") for ts in t["raw_timestamps"]]
        incidents = detect_incidents(all_ts_str, t["raw_latencies"], t["raw_losses"], t["name"])

        result["targets"].append({
            "name": t["name"],
            "ip": ip,
            "avg_latency": avg_lat,
            "p50_latency": p50,
            "p95_latency": p95,
            "p99_latency": p99,
            "max_latency": lat_max,
            "loss_pct": loss_pct,
            "total_probes": t["total"],
            "lost_probes": t["lost"],
            "jitter": jitter,
            "chart_timestamps": chart_ts,
            "chart_latencies": chart_lat,
            "chart_moving_avg": chart_ma,
            "chart_losses": chart_loss,
            "incidents": incidents,
        })

    # Analysis
    result["analysis"] = build_analysis(result["targets"])
    result["remediation"] = build_remediation(result["targets"])

    # Verdict
    router = next((t for t in result["targets"] if "192.168" in t["ip"] or "10.0" in t["ip"]), None)
    inet = next((t for t in result["targets"] if t["ip"] == "1.1.1.1"), None)

    if router and router["loss_pct"] >= 5:
        result["verdict"] = "router_bad"
        result["verdict_text"] = "Your router/Wi-Fi is the problem"
        result["verdict_detail"] = f"Router packet loss: {router['loss_pct']}%"
    elif router and inet and inet["loss_pct"] >= 5 and router["loss_pct"] < 2:
        result["verdict"] = "isp_bad"
        result["verdict_text"] = "Cox is the problem"
        result["verdict_detail"] = f"Router loss: {router['loss_pct']}% | Internet loss: {inet['loss_pct']}%"
    elif router and inet and inet["loss_pct"] >= 1.5 and router["loss_pct"] < 1:
        result["verdict"] = "isp_maybe"
        result["verdict_text"] = "Evidence building against Cox"
        result["verdict_detail"] = f"Router clean ({router['loss_pct']}%) but upstream loss at {inet['loss_pct']}%"
    elif router and router["p95_latency"] > 80 and router["p50_latency"] < 10:
        result["verdict"] = "router_spiky"
        result["verdict_text"] = "Router latency is unstable"
        result["verdict_detail"] = f"Median {router['p50_latency']}ms but P95 {router['p95_latency']}ms"
    else:
        result["verdict"] = "healthy"
        result["verdict_text"] = "Network looks healthy"
        result["verdict_detail"] = "No significant issues detected in this window"

    return result


class DashboardHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        if self.path.startswith("/api/data"):
            mins = 60
            if "minutes=" in self.path:
                try:
                    mins = int(self.path.split("minutes=")[1].split("&")[0])
                except (IndexError, ValueError):
                    pass
            self.send_json(parse_csv_data(get_latest_log(), minutes=mins))
        elif self.path == "/api/status":
            pid_file = LOG_DIR / ".netprobe.pid"
            daemon_running = False
            daemon_pid = None
            if pid_file.exists():
                try:
                    pid = int(pid_file.read_text().strip())
                    os.kill(pid, 0)
                    daemon_running = True
                    daemon_pid = pid
                except (ProcessLookupError, ValueError):
                    pass
            log = get_latest_log()
            probe_count = 0
            if log:
                try:
                    with open(log) as f:
                        probe_count = sum(1 for _ in f) - 1
                except:
                    pass
            self.send_json({
                "daemon_running": daemon_running,
                "daemon_pid": daemon_pid,
                "log_file": str(log) if log else None,
                "total_probes": probe_count,
            })
        elif self.path == "/api/settings/password/check":
            self.handle_password_check()
        elif self.path.startswith("/api/router/status"):
            self.handle_router_status()
        elif self.path.startswith("/api/export/csv"):
            self.handle_export_csv()
        elif self.path.startswith("/api/export/json"):
            self.handle_export_json()
        else:
            self.send_html()

    def send_json(self, data):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def send_html(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(DASHBOARD_HTML.encode())

    def handle_password_check(self):
        self.send_json({"stored": password_is_stored()})

    def handle_router_status(self):
        try:
            password = retrieve_password()
            if not password:
                self.send_json({"error": "No password stored"})
                return
            script = Path.home() / "network-monitor" / "router_login.mjs"
            result = subprocess.run(
                ["node", str(script), "status"],
                input=password, capture_output=True, text=True, timeout=30
            )
            if result.returncode != 0:
                self.send_json({"error": result.stderr.strip() or "Command failed"})
                return
            data = json.loads(result.stdout)
            self.send_json(data)
        except json.JSONDecodeError:
            self.send_json({"error": "Invalid JSON from router"})
        except subprocess.TimeoutExpired:
            self.send_json({"error": "Router connection timed out"})
        except Exception as e:
            self.send_json({"error": str(e)})

    def handle_export_csv(self):
        mins = 60
        if "minutes=" in self.path:
            try:
                mins = int(self.path.split("minutes=")[1].split("&")[0])
            except (IndexError, ValueError):
                pass
        log = get_latest_log()
        if not log:
            self.send_response(404)
            self.end_headers()
            return
        cutoff = datetime.now() - timedelta(minutes=mins)
        lines = []
        files_to_read = [log]
        if mins > 120:
            for f in get_all_logs():
                if f != log and f.stat().st_size > 50:
                    files_to_read.append(f)
        header_written = False
        for fpath in files_to_read:
            try:
                with open(fpath) as f:
                    for i, line in enumerate(f):
                        if i == 0 and not header_written:
                            lines.append(line)
                            header_written = True
                        elif i > 0:
                            try:
                                ts_str = line.split(",")[0]
                                ts = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
                                if ts >= cutoff:
                                    lines.append(line)
                            except (ValueError, IndexError):
                                continue
            except Exception:
                continue
        content = "".join(lines)
        self.send_response(200)
        self.send_header("Content-Type", "text/csv")
        self.send_header("Content-Disposition", f"attachment; filename=notmyrouter_{mins}min.csv")
        self.end_headers()
        self.wfile.write(content.encode())

    def handle_export_json(self):
        mins = 60
        if "minutes=" in self.path:
            try:
                mins = int(self.path.split("minutes=")[1].split("&")[0])
            except (IndexError, ValueError):
                pass
        data = parse_csv_data(get_latest_log(), minutes=mins)
        content = json.dumps(data, indent=2)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Disposition", f"attachment; filename=notmyrouter_{mins}min.json")
        self.end_headers()
        self.wfile.write(content.encode())

    def do_POST(self):
        if self.path == "/api/settings/password":
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length)) if length else {}
            password = body.get("password", "")
            if not password:
                self.send_json({"success": False, "error": "No password provided"})
                return
            success, error = store_password(password)
            if success:
                self.send_json({"success": True})
            else:
                self.send_json({"success": False, "error": error})
        else:
            self.send_response(404)
            self.end_headers()


DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NotMyRouter</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.7"></script>
<style>
  :root {
    --bg: #0a0a0f; --surface: #12131a; --surface2: #1a1b24;
    --border: #2a2b35; --border-light: #3a3b45;
    --text: #e8eaed; --text-dim: #6b7280; --text-muted: #4b5060;
    --green: #22c55e; --green-dim: rgba(34,197,94,0.12);
    --yellow: #eab308; --yellow-dim: rgba(234,179,8,0.12);
    --red: #ef4444; --red-dim: rgba(239,68,68,0.12);
    --blue: #3b82f6; --blue-dim: rgba(59,130,246,0.12);
    --purple: #a78bfa; --purple-dim: rgba(167,139,250,0.12);
    --orange: #f97316;
  }
  * { margin:0; padding:0; box-sizing:border-box; }
  body { background:var(--bg); color:var(--text); font-family:'SF Pro Text',-apple-system,BlinkMacSystemFont,system-ui,sans-serif; }
  .container { max-width:1400px; margin:0 auto; padding:20px 24px; }

  /* Header */
  .header { display:flex; align-items:center; justify-content:space-between; margin-bottom:20px; flex-wrap:wrap; gap:12px; }
  .brand { display:flex; align-items:baseline; gap:10px; }
  .brand h1 { font-size:22px; font-weight:800; letter-spacing:-0.5px; background:linear-gradient(135deg, #ef4444 0%, #f97316 50%, #eab308 100%); -webkit-background-clip:text; -webkit-text-fill-color:transparent; }
  .brand .sub { font-size:12px; color:var(--text-dim); font-weight:400; }
  .controls { display:flex; gap:8px; align-items:center; flex-wrap:wrap; }
  .time-picker { display:flex; gap:2px; background:var(--surface); border-radius:8px; padding:2px; border:1px solid var(--border); }
  .time-picker button { background:transparent; border:none; color:var(--text-dim); padding:5px 12px; border-radius:6px; cursor:pointer; font-size:12px; font-weight:500; transition:all 0.15s; }
  .time-picker button:hover { color:var(--text); }
  .time-picker button.active { background:var(--blue); color:#fff; }
  .pill { padding:3px 10px; border-radius:16px; font-size:11px; font-weight:600; display:inline-flex; align-items:center; gap:5px; }
  .pill.green { background:var(--green-dim); color:var(--green); }
  .pill.red { background:var(--red-dim); color:var(--red); }
  .pill.blue { background:var(--blue-dim); color:var(--blue); }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }
  .live-dot { width:6px; height:6px; border-radius:50%; background:var(--green); display:inline-block; animation:pulse 2s ease-in-out infinite; }

  /* Verdict */
  .verdict { border-radius:12px; padding:16px 20px; margin-bottom:20px; display:flex; align-items:center; gap:16px; }
  .verdict.healthy { background:var(--green-dim); border:1px solid rgba(34,197,94,0.25); }
  .verdict.isp_bad { background:var(--red-dim); border:1px solid rgba(239,68,68,0.25); }
  .verdict.isp_maybe { background:var(--yellow-dim); border:1px solid rgba(234,179,8,0.25); }
  .verdict.router_bad { background:var(--orange); background:rgba(249,115,22,0.12); border:1px solid rgba(249,115,22,0.25); }
  .verdict.router_spiky { background:var(--yellow-dim); border:1px solid rgba(234,179,8,0.25); }
  .verdict.loading { background:var(--surface); border:1px solid var(--border); }
  .verdict-icon { font-size:28px; flex-shrink:0; }
  .verdict-text h2 { font-size:16px; font-weight:700; margin-bottom:2px; }
  .verdict-text p { font-size:13px; color:var(--text-dim); }

  /* Two-column layout */
  .layout { display:grid; grid-template-columns:1fr 380px; gap:20px; }
  @media (max-width:1100px) { .layout { grid-template-columns:1fr; } }

  /* Cards */
  .card { background:var(--surface); border:1px solid var(--border); border-radius:12px; padding:18px; margin-bottom:16px; }
  .card-header { display:flex; justify-content:space-between; align-items:center; margin-bottom:14px; }
  .card-title { font-size:13px; font-weight:600; }
  .card-subtitle { font-size:11px; color:var(--text-dim); font-family:'SF Mono',monospace; }

  /* Stats row */
  .stats-row { display:grid; grid-template-columns:repeat(6,1fr); gap:8px; margin-bottom:14px; }
  .stat { text-align:center; padding:8px 4px; background:var(--surface2); border-radius:8px; }
  .stat-val { font-size:16px; font-weight:700; font-variant-numeric:tabular-nums; line-height:1.2; }
  .stat-lbl { font-size:9px; color:var(--text-muted); text-transform:uppercase; letter-spacing:0.5px; margin-top:2px; }

  /* Chart */
  .chart-wrap { height:180px; position:relative; }

  /* Analysis panel */
  .analysis-panel { }
  .analysis-panel h3 { font-size:13px; font-weight:600; color:var(--text-dim); text-transform:uppercase; letter-spacing:0.5px; margin-bottom:12px; }
  .finding { padding:14px; border-radius:10px; margin-bottom:10px; border-left:3px solid var(--border); }
  .finding.critical { background:var(--red-dim); border-left-color:var(--red); }
  .finding.warning { background:var(--yellow-dim); border-left-color:var(--yellow); }
  .finding.ok { background:var(--green-dim); border-left-color:var(--green); }
  .finding.info { background:var(--blue-dim); border-left-color:var(--blue); }
  .finding-title { font-size:13px; font-weight:700; margin-bottom:4px; }
  .finding.critical .finding-title { color:var(--red); }
  .finding.warning .finding-title { color:var(--yellow); }
  .finding.ok .finding-title { color:var(--green); }
  .finding.info .finding-title { color:var(--blue); }
  .finding-detail { font-size:12px; color:var(--text-dim); line-height:1.5; }

  /* Incident log */
  .incidents h3 { font-size:13px; font-weight:600; color:var(--text-dim); text-transform:uppercase; letter-spacing:0.5px; margin-bottom:12px; }
  .incident { display:flex; gap:10px; padding:8px 0; border-bottom:1px solid var(--border); font-size:12px; align-items:center; }
  .incident:last-child { border-bottom:none; }
  .incident-time { color:var(--text-muted); font-family:'SF Mono',monospace; font-size:11px; white-space:nowrap; }
  .incident-badge { padding:2px 6px; border-radius:4px; font-size:10px; font-weight:600; white-space:nowrap; }
  .incident-badge.loss { background:var(--red-dim); color:var(--red); }
  .incident-badge.spike { background:var(--yellow-dim); color:var(--yellow); }
  .incident-target { color:var(--text-dim); }
  .incident-detail { color:var(--text); }

  /* Footer */
  .footer { text-align:center; padding:16px; color:var(--text-muted); font-size:11px; }

  /* Section 2: Remediation */
  .section-divider { margin:40px 0 24px; padding-top:32px; border-top:1px solid var(--border); }
  .section-title { font-size:20px; font-weight:800; background:linear-gradient(135deg, #ef4444 0%, #f97316 50%, #eab308 100%); -webkit-background-clip:text; -webkit-text-fill-color:transparent; margin-bottom:4px; }
  .section-sub { font-size:13px; color:var(--text-dim); margin-bottom:20px; }

  .remediation-tabs { display:flex; gap:2px; background:var(--surface); border-radius:10px; padding:3px; border:1px solid var(--border); margin-bottom:20px; width:fit-content; }
  .rem-tab { background:transparent; border:none; color:var(--text-dim); padding:8px 20px; border-radius:8px; cursor:pointer; font-size:13px; font-weight:600; transition:all 0.15s; }
  .rem-tab:hover { color:var(--text); }
  .rem-tab.active { background:var(--red); color:#fff; }

  .script-box { background:var(--surface2); border:1px solid var(--border); border-radius:8px; padding:16px; font-size:13px; line-height:1.7; color:var(--text); margin-bottom:12px; }
  .copy-btn { background:var(--surface2); border:1px solid var(--border); color:var(--text-dim); padding:6px 14px; border-radius:6px; font-size:11px; cursor:pointer; transition:all 0.15s; }
  .copy-btn:hover { background:var(--blue); color:#fff; border-color:var(--blue); }

  .counter-item { border-bottom:1px solid var(--border); padding:14px 0; }
  .counter-item:last-child { border-bottom:none; }
  .counter-move { font-size:12px; font-weight:700; color:var(--red); margin-bottom:6px; text-transform:uppercase; letter-spacing:0.3px; }
  .counter-response { font-size:13px; color:var(--text); line-height:1.6; background:var(--surface2); padding:12px; border-radius:8px; border-left:3px solid var(--green); }

  .phrase-grid { display:flex; flex-wrap:wrap; gap:6px; }
  .phrase-chip { background:var(--surface2); border:1px solid var(--border); padding:6px 12px; border-radius:6px; font-size:12px; font-family:'SF Mono',monospace; color:var(--blue); cursor:pointer; transition:all 0.15s; }
  .phrase-chip:hover { background:var(--blue-dim); border-color:var(--blue); }

  .two-col { display:grid; grid-template-columns:1fr 1fr; gap:16px; margin-bottom:16px; }
  @media (max-width:900px) { .two-col { grid-template-columns:1fr; } }

  .esc-step { padding:12px 0; border-bottom:1px solid var(--border); }
  .esc-step:last-child { border-bottom:none; }
  .esc-step-name { font-size:13px; font-weight:700; color:var(--text); margin-bottom:4px; }
  .esc-step-action { font-size:12px; color:var(--text-dim); line-height:1.5; margin-bottom:4px; }
  .esc-step-blocked { font-size:11px; color:var(--yellow); font-style:italic; }

  .outcome-item { display:flex; justify-content:space-between; align-items:center; padding:10px 0; border-bottom:1px solid var(--border); }
  .outcome-item:last-child { border-bottom:none; }
  .outcome-name { font-size:13px; font-weight:600; }
  .outcome-detail { font-size:11px; color:var(--text-dim); margin-top:2px; }
  .likelihood { padding:2px 8px; border-radius:4px; font-size:10px; font-weight:700; text-transform:uppercase; white-space:nowrap; }
  .likelihood.high { background:var(--green-dim); color:var(--green); }
  .likelihood.medium { background:var(--yellow-dim); color:var(--yellow); }
  .likelihood.low { background:var(--red-dim); color:var(--red); }

  .setting-item { border-bottom:1px solid var(--border); padding:14px 0; }
  .setting-item:last-child { border-bottom:none; }
  .setting-header { display:flex; justify-content:space-between; align-items:center; margin-bottom:6px; flex-wrap:wrap; gap:4px; }
  .setting-name { font-size:13px; font-weight:700; color:var(--text); }
  .setting-value { font-size:11px; font-family:'SF Mono',monospace; padding:2px 8px; background:var(--red-dim); color:var(--red); border-radius:4px; font-weight:600; }
  .setting-location { font-size:11px; color:var(--text-muted); margin-bottom:6px; font-family:'SF Mono',monospace; }
  .setting-why { font-size:12px; color:var(--text-dim); line-height:1.5; margin-bottom:6px; }
  .setting-result { font-size:12px; color:var(--green); font-weight:500; }

  .diag-item { background:var(--yellow-dim); border-left:3px solid var(--yellow); padding:12px; border-radius:8px; margin-bottom:8px; font-size:13px; line-height:1.5; color:var(--text); }

  .fw-info { font-size:13px; line-height:1.6; }
  .fw-info strong { color:var(--text); }
  .fw-info .fw-note { color:var(--text-dim); font-size:12px; margin-top:8px; }
  .fw-link { color:var(--blue); text-decoration:none; }
  .fw-link:hover { text-decoration:underline; }

  .test-proc { font-size:13px; line-height:1.7; color:var(--text); }

  /* Compare overlay chart */
  .compare-card .chart-wrap { height:220px; }

  /* Settings */
  .settings-cog { background:var(--surface); border:1px solid var(--border); color:var(--text-dim); width:32px; height:32px; border-radius:50%; cursor:pointer; font-size:16px; display:inline-flex; align-items:center; justify-content:center; transition:all 0.15s; }
  .settings-cog:hover { color:var(--text); background:var(--surface2); border-color:var(--border-light); }
  .settings-cog.active { background:var(--blue); color:#fff; border-color:var(--blue); }
  #settings-overlay { display:none; background:var(--bg); border-bottom:1px solid var(--border); padding:20px 0; margin-bottom:20px; }
  #settings-overlay.open { display:block; }
  .settings-grid { display:grid; grid-template-columns:repeat(3,1fr); gap:16px; }
  @media (max-width:900px) { .settings-grid { grid-template-columns:1fr; } }
  .settings-card { background:var(--surface); border:1px solid var(--border); border-radius:12px; padding:18px; }
  .settings-card h3 { font-size:14px; font-weight:700; margin-bottom:12px; }
  .settings-input { background:var(--surface2); border:1px solid var(--border); border-radius:6px; padding:8px 12px; color:var(--text); font-size:13px; width:100%; outline:none; }
  .settings-input:focus { border-color:var(--blue); }
  .settings-btn { background:var(--surface2); border:1px solid var(--border); color:var(--text-dim); padding:8px 16px; border-radius:6px; font-size:12px; cursor:pointer; transition:all 0.15s; font-weight:500; }
  .settings-btn:hover { background:var(--blue); color:#fff; border-color:var(--blue); }
  .settings-btn.primary { background:var(--blue); color:#fff; border-color:var(--blue); }
  .settings-btn.primary:hover { background:#2563eb; }
  .settings-row { display:flex; gap:8px; align-items:center; margin-bottom:12px; }
  .settings-status { font-size:11px; font-weight:600; }
  .settings-status.ok { color:var(--green); }
  .settings-status.none { color:var(--text-muted); }
  .stats-kv { display:grid; grid-template-columns:auto 1fr; gap:4px 12px; font-size:12px; }
  .stats-kv dt { color:var(--text-muted); }
  .stats-kv dd { color:var(--text); font-family:'SF Mono',monospace; font-size:11px; margin:0; }
</style>
</head>
<body>
<div class="container">

<div class="header">
  <div class="brand">
    <h1>NOTMYROUTER</h1>
    <span class="sub">network evidence dashboard</span>
  </div>
  <div class="controls">
    <div class="time-picker">
      <button onclick="setWindow(5)" id="btn-5">5m</button>
      <button onclick="setWindow(15)" id="btn-15">15m</button>
      <button onclick="setWindow(60)" id="btn-60" class="active">1h</button>
      <button onclick="setWindow(360)" id="btn-360">6h</button>
      <button onclick="setWindow(1440)" id="btn-1440">24h</button>
    </div>
    <span id="daemon-status"></span>
    <span id="probe-count" class="pill blue"></span>
    <span id="last-update" class="pill blue"></span>
    <button class="settings-cog" onclick="toggleSettings()" title="Settings" id="settings-cog-btn">&#9881;</button>
  </div>
</div>

<div id="settings-overlay">
  <div class="settings-grid">
    <div class="settings-card">
      <h3>Router Password</h3>
      <div class="settings-row">
        <input type="password" class="settings-input" id="settings-password" placeholder="Router admin password">
        <button class="settings-btn primary" onclick="savePassword()">Save</button>
      </div>
      <div class="settings-row">
        <span class="settings-status" id="password-status">Checking...</span>
        <button class="settings-btn" onclick="testConnection()" id="test-conn-btn">Test Connection</button>
      </div>
    </div>
    <div class="settings-card">
      <h3>Router &amp; Network Stats</h3>
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
        <span class="settings-status" id="stats-status"></span>
        <button class="settings-btn" onclick="fetchRouterStatus()" id="refresh-stats-btn">Refresh</button>
      </div>
      <dl class="stats-kv" id="router-stats-grid">
        <dt>Status</dt><dd id="rs-status">-</dd>
      </dl>
    </div>
    <div class="settings-card">
      <h3>Data Export</h3>
      <p style="font-size:12px; color:var(--text-dim); margin-bottom:12px;">Export data for the current time window (<span id="export-window">60</span> min)</p>
      <div class="settings-row">
        <button class="settings-btn" onclick="exportData('csv')">Export CSV</button>
        <button class="settings-btn" onclick="exportData('json')">Export JSON</button>
      </div>
    </div>
  </div>
</div>

<div id="verdict" class="verdict loading">
  <div class="verdict-icon" id="verdict-icon">...</div>
  <div class="verdict-text">
    <h2 id="verdict-title">Connecting...</h2>
    <p id="verdict-detail">Waiting for data</p>
  </div>
</div>

<!-- Overlay comparison chart -->
<div class="card compare-card">
  <div class="card-header">
    <span class="card-title">Latency Comparison (Moving Average)</span>
    <span class="card-subtitle" id="compare-subtitle">all targets overlaid</span>
  </div>
  <div class="chart-wrap"><canvas id="chart-compare"></canvas></div>
</div>

<div class="layout">
  <div class="main-col">
    <div id="target-cards"></div>
  </div>
  <div class="side-col">
    <div class="analysis-panel">
      <h3>Analysis</h3>
      <div id="analysis-list"></div>
    </div>
    <div class="incidents card" id="incidents-card" style="display:none; margin-top:16px;">
      <h3>Recent Incidents</h3>
      <div id="incident-list"></div>
    </div>
  </div>
</div>

<!-- ==================== SECTION 2: REMEDIATION ==================== -->
<div class="section-divider">
  <h2 class="section-title">Remediation</h2>
  <p class="section-sub">Data-driven action plan updated with your live monitoring data</p>
</div>

<div class="remediation-tabs">
  <button class="rem-tab active" onclick="showRemTab('cox')" id="rem-tab-cox">Cox Call Script</button>
  <button class="rem-tab" onclick="showRemTab('router')" id="rem-tab-router">TP-Link BE10000 Fixes</button>
</div>

<!-- Cox Panel -->
<div id="rem-cox" class="rem-panel">
  <div class="card">
    <div class="card-header"><span class="card-title">Opening Script (read this verbatim)</span><span class="card-subtitle">auto-populated with your live data</span></div>
    <div class="script-box" id="cox-opening"></div>
    <button class="copy-btn" onclick="copyText('cox-opening')">Copy to clipboard</button>
  </div>

  <div class="card">
    <div class="card-header"><span class="card-title">Counter Their Script</span><span class="card-subtitle">what they'll say and how to respond</span></div>
    <div id="cox-counters"></div>
  </div>

  <div class="card">
    <div class="card-header"><span class="card-title">Magic Phrases</span><span class="card-subtitle">terminology that signals you know your stuff</span></div>
    <div id="cox-phrases" class="phrase-grid"></div>
  </div>

  <div class="two-col">
    <div class="card">
      <div class="card-header"><span class="card-title">Escalation Ladder</span></div>
      <div id="cox-escalation"></div>
    </div>
    <div class="card">
      <div class="card-header"><span class="card-title">Expected Outcomes</span></div>
      <div id="cox-outcomes"></div>
    </div>
  </div>
</div>

<!-- Router Panel -->
<div id="rem-router" class="rem-panel" style="display:none">
  <div class="card" id="router-diagnosis-card">
    <div class="card-header"><span class="card-title">Your Router Diagnosis</span><span class="card-subtitle">TP-Link Archer BE800 (BE10000)</span></div>
    <div id="router-diagnosis"></div>
  </div>

  <div class="card">
    <div class="card-header"><span class="card-title">High-Impact Settings Changes</span><span class="card-subtitle">start here - change one at a time</span></div>
    <div id="router-high"></div>
  </div>

  <div class="card">
    <div class="card-header"><span class="card-title">Medium-Impact Settings</span></div>
    <div id="router-medium"></div>
  </div>

  <div class="two-col">
    <div class="card">
      <div class="card-header"><span class="card-title">Firmware</span></div>
      <div id="router-firmware"></div>
    </div>
    <div class="card">
      <div class="card-header"><span class="card-title">Testing Procedure</span></div>
      <div id="router-testing"></div>
    </div>
  </div>
</div>

<div class="footer">
  Auto-refreshes every 10s &middot; <span id="log-file"></span>
</div>

</div>

<script>
function h(s) { const d = document.createElement('div'); d.textContent = String(s ?? ''); return d.innerHTML; }
let charts = {};
let currentMinutes = 60;
const TARGET_COLORS = {
  'Router/Gateway': {line:'#22c55e', fill:'rgba(34,197,94,0.08)', ma:'rgba(34,197,94,0.5)'},
  'Cloudflare DNS': {line:'#3b82f6', fill:'rgba(59,130,246,0.08)', ma:'rgba(59,130,246,0.5)'},
  'Google DNS':     {line:'#a78bfa', fill:'rgba(167,139,250,0.08)', ma:'rgba(167,139,250,0.5)'},
};
const VERDICT_ICONS = {
  healthy:'&#10004;&#65039;', isp_bad:'&#128680;', isp_maybe:'&#9888;&#65039;',
  router_bad:'&#128295;', router_spiky:'&#128200;', loading:'&#8987;'
};

function setWindow(mins) {
  currentMinutes = mins;
  document.querySelectorAll('.time-picker button').forEach(b => b.classList.remove('active'));
  const btn = document.getElementById('btn-'+mins);
  if(btn) btn.classList.add('active');
  // Destroy all charts so they rebuild cleanly
  Object.values(charts).forEach(c => c.destroy());
  charts = {};
  document.getElementById('target-cards').innerHTML = '';
  fetchData();
}

function colorForValue(val, thresholds) {
  if (val >= thresholds[1]) return 'var(--red)';
  if (val >= thresholds[0]) return 'var(--yellow)';
  return 'var(--green)';
}

async function fetchData() {
  try {
    const [dataRes, statusRes] = await Promise.all([
      fetch('/api/data?minutes=' + currentMinutes),
      fetch('/api/status'),
    ]);
    const data = await dataRes.json();
    const status = await statusRes.json();

    // Status pills
    const ds = document.getElementById('daemon-status');
    ds.innerHTML = status.daemon_running
      ? '<span class="pill green"><span class="live-dot"></span> Collecting</span>'
      : '<span class="pill red">Daemon stopped</span>';
    document.getElementById('probe-count').textContent = (status.total_probes || 0) + ' probes';
    document.getElementById('last-update').textContent = data.generated || '...';
    document.getElementById('log-file').textContent = (data.log_file||'').split('/').pop() || '';

    // Verdict
    const vEl = document.getElementById('verdict');
    vEl.className = 'verdict ' + (data.verdict || 'loading');
    document.getElementById('verdict-icon').innerHTML = VERDICT_ICONS[data.verdict] || '...';
    document.getElementById('verdict-title').textContent = data.verdict_text || 'Loading...';
    document.getElementById('verdict-detail').textContent = data.verdict_detail || '';

    if (!data.targets || data.targets.length === 0) return;

    // ---- Comparison overlay chart ----
    buildCompareChart(data.targets);

    // ---- Per-target cards ----
    const container = document.getElementById('target-cards');
    data.targets.forEach((t, i) => {
      let card = document.getElementById('tcard-'+i);
      if (!card) {
        card = document.createElement('div');
        card.className = 'card';
        card.id = 'tcard-'+i;
        card.innerHTML = `
          <div class="card-header">
            <span class="card-title" id="tc${i}-name"></span>
            <span class="card-subtitle" id="tc${i}-ip"></span>
          </div>
          <div class="stats-row">
            <div class="stat"><div class="stat-val" id="tc${i}-loss">-</div><div class="stat-lbl">Loss</div></div>
            <div class="stat"><div class="stat-val" id="tc${i}-p50">-</div><div class="stat-lbl">Median</div></div>
            <div class="stat"><div class="stat-val" id="tc${i}-avg">-</div><div class="stat-lbl">Avg</div></div>
            <div class="stat"><div class="stat-val" id="tc${i}-p95">-</div><div class="stat-lbl">P95</div></div>
            <div class="stat"><div class="stat-val" id="tc${i}-max">-</div><div class="stat-lbl">Max</div></div>
            <div class="stat"><div class="stat-val" id="tc${i}-jitter">-</div><div class="stat-lbl">Jitter</div></div>
          </div>
          <div class="chart-wrap"><canvas id="tchart-${i}"></canvas></div>
        `;
        container.appendChild(card);
      }

      const isRouter = t.ip.startsWith('192.168') || t.ip.startsWith('10.0');
      document.getElementById('tc'+i+'-name').textContent = t.name;
      document.getElementById('tc'+i+'-ip').textContent = t.ip;

      const lossEl = document.getElementById('tc'+i+'-loss');
      lossEl.textContent = t.loss_pct + '%';
      lossEl.style.color = colorForValue(t.loss_pct, [1, 5]);

      const p50El = document.getElementById('tc'+i+'-p50');
      p50El.textContent = t.p50_latency;
      p50El.style.color = isRouter ? colorForValue(t.p50_latency, [10, 30]) : 'var(--text)';

      const avgEl = document.getElementById('tc'+i+'-avg');
      avgEl.textContent = t.avg_latency;
      avgEl.style.color = isRouter ? colorForValue(t.avg_latency, [15, 50]) : colorForValue(t.avg_latency, [80, 150]);

      document.getElementById('tc'+i+'-p95').textContent = t.p95_latency;
      document.getElementById('tc'+i+'-max').textContent = t.max_latency;
      document.getElementById('tc'+i+'-jitter').textContent = t.jitter;

      // Individual chart
      buildTargetChart(i, t);
    });

    // ---- Analysis findings ----
    const aList = document.getElementById('analysis-list');
    aList.innerHTML = (data.analysis || []).map(f =>
      `<div class="finding ${h(f.severity)}">
        <div class="finding-title">${h(f.title)}</div>
        <div class="finding-detail">${h(f.detail)}</div>
      </div>`
    ).join('');

    // ---- Incidents ----
    buildIncidents(data.targets);

    // ---- Remediation ----
    if (data.remediation) buildRemediation(data.remediation);

  } catch(e) {
    console.error('Fetch error:', e);
  }
}

function showRemTab(tab) {
  document.querySelectorAll('.rem-panel').forEach(p => p.style.display='none');
  document.querySelectorAll('.rem-tab').forEach(t => t.classList.remove('active'));
  document.getElementById('rem-'+tab).style.display='block';
  document.getElementById('rem-tab-'+tab).classList.add('active');
}

function copyText(id) {
  const el = document.getElementById(id);
  navigator.clipboard.writeText(el.innerText);
  const btn = el.parentElement.querySelector('.copy-btn');
  btn.textContent = 'Copied!';
  setTimeout(()=> btn.textContent='Copy to clipboard', 2000);
}

function buildRemediation(rem) {
  const cox = rem.cox || {};
  const rtr = rem.router || {};

  // Cox opening script
  const opening = document.getElementById('cox-opening');
  if (cox.opening_script) opening.textContent = cox.opening_script;

  // Cox counters
  const counters = document.getElementById('cox-counters');
  if (cox.counters) {
    counters.innerHTML = cox.counters.map(c =>
      `<div class="counter-item">
        <div class="counter-move">They say: "${h(c.their_move)}"</div>
        <div class="counter-response">${h(c.your_response)}</div>
      </div>`
    ).join('');
  }

  // Magic phrases
  const phrases = document.getElementById('cox-phrases');
  if (cox.magic_phrases) {
    phrases.innerHTML = cox.magic_phrases.map(p =>
      `<span class="phrase-chip" onclick="navigator.clipboard.writeText(this.dataset.v)" data-v="${h(p)}" title="Click to copy">${h(p)}</span>`
    ).join('');
  }

  // Escalation
  const esc = document.getElementById('cox-escalation');
  if (cox.escalation_steps) {
    esc.innerHTML = cox.escalation_steps.map((s,i) =>
      `<div class="esc-step">
        <div class="esc-step-name">Step ${i+1}: ${h(s.step)}</div>
        <div class="esc-step-action">${h(s.action)}</div>
        <div class="esc-step-blocked">${h(s.if_blocked)}</div>
      </div>`
    ).join('');
  }

  // Outcomes
  const outcomes = document.getElementById('cox-outcomes');
  if (cox.expected_outcomes) {
    outcomes.innerHTML = cox.expected_outcomes.map(o =>
      `<div class="outcome-item">
        <div>
          <div class="outcome-name">${h(o.outcome)}</div>
          <div class="outcome-detail">${h(o.detail)}</div>
        </div>
        <span class="likelihood ${h(o.likelihood)}">${h(o.likelihood)}</span>
      </div>`
    ).join('');
  }

  // Router diagnosis
  const diag = document.getElementById('router-diagnosis');
  if (rtr.diagnosis && rtr.diagnosis.length) {
    diag.innerHTML = rtr.diagnosis.map(d => `<div class="diag-item">${h(d)}</div>`).join('');
  } else {
    diag.innerHTML = '<div class="diag-item" style="border-left-color:var(--green); background:var(--green-dim);">Router metrics look acceptable. Monitor for intermittent issues.</div>';
  }

  // High impact settings
  const high = document.getElementById('router-high');
  if (rtr.high_impact) {
    high.innerHTML = rtr.high_impact.map(s =>
      `<div class="setting-item">
        <div class="setting-header">
          <span class="setting-name">${s.setting}</span>
          <span class="setting-value">${s.value}</span>
        </div>
        <div class="setting-location">${s.location}</div>
        <div class="setting-why">${s.why}</div>
        <div class="setting-result">${s.expected_result}</div>
      </div>`
    ).join('');
  }

  // Medium impact settings
  const med = document.getElementById('router-medium');
  if (rtr.medium_impact) {
    med.innerHTML = rtr.medium_impact.map(s =>
      `<div class="setting-item">
        <div class="setting-header">
          <span class="setting-name">${s.setting}</span>
          <span class="setting-value">${s.value}</span>
        </div>
        <div class="setting-location">${s.location}</div>
        <div class="setting-why">${s.why}</div>
        <div class="setting-result">${s.expected_result}</div>
      </div>`
    ).join('');
  }

  // Firmware
  const fw = document.getElementById('router-firmware');
  if (rtr.firmware) {
    fw.innerHTML = `<div class="fw-info">
      <p><strong>Recommended:</strong> ${rtr.firmware.current_recommended}</p>
      <p><strong>Stable fallback:</strong> ${rtr.firmware.stable_fallback}</p>
      <p class="fw-note">${rtr.firmware.note}</p>
      <p style="margin-top:8px"><a class="fw-link" href="${rtr.firmware.url}" target="_blank">TP-Link Download Page</a></p>
    </div>`;
  }

  // Testing procedure
  const test = document.getElementById('router-testing');
  if (rtr.test_procedure) {
    test.innerHTML = `<div class="test-proc">${rtr.test_procedure}</div>`;
  }
}

function buildCompareChart(targets) {
  const ctx = document.getElementById('chart-compare');
  const datasets = targets.map(t => {
    const c = TARGET_COLORS[t.name] || {ma:'#58a6ff'};
    return {
      label: t.name,
      data: t.chart_moving_avg,
      borderColor: c.ma,
      borderWidth: 2,
      fill: false,
      pointRadius: 0,
      tension: 0.4,
    };
  });

  // Use longest timestamp array
  const labels = targets.reduce((a,b) => a.chart_timestamps.length >= b.chart_timestamps.length ? a : b).chart_timestamps;

  if (charts['compare']) {
    const c = charts['compare'];
    c.data.labels = labels;
    datasets.forEach((ds, i) => {
      if (c.data.datasets[i]) {
        c.data.datasets[i].data = ds.data;
      }
    });
    c.update('none');
  } else {
    charts['compare'] = new Chart(ctx, {
      type: 'line',
      data: { labels, datasets },
      options: {
        responsive:true, maintainAspectRatio:false, animation:false,
        interaction:{mode:'index', intersect:false},
        plugins: {
          legend:{position:'top', labels:{color:'#6b7280', usePointStyle:true, pointStyle:'circle', padding:16, font:{size:11}}},
          tooltip:{backgroundColor:'#1a1b24', titleColor:'#e8eaed', bodyColor:'#6b7280', borderColor:'#2a2b35', borderWidth:1,
            callbacks:{label:ctx=>ctx.dataset.label+': '+ctx.parsed.y+'ms'}
          }
        },
        scales: {
          x:{ticks:{color:'#3a3b45', maxTicksLimit:8, font:{size:10}}, grid:{color:'#1a1b24'}},
          y:{ticks:{color:'#3a3b45', font:{size:10}, callback:v=>v+'ms'}, grid:{color:'#1a1b24'}, beginAtZero:true},
        }
      }
    });
  }
}

function buildTargetChart(i, t) {
  const key = 'target-'+i;
  const ctx = document.getElementById('tchart-'+i);
  const colors = TARGET_COLORS[t.name] || {line:'#3b82f6', fill:'rgba(59,130,246,0.08)', ma:'rgba(59,130,246,0.5)'};

  // Loss markers: show as red dots at y=0
  const lossPoints = t.chart_latencies.map((v,j) => t.chart_losses[j]===100 ? 0 : null);

  if (charts[key]) {
    const c = charts[key];
    c.data.labels = t.chart_timestamps;
    c.data.datasets[0].data = t.chart_latencies;
    c.data.datasets[1].data = t.chart_moving_avg;
    c.data.datasets[2].data = lossPoints;
    c.update('none');
  } else {
    charts[key] = new Chart(ctx, {
      type:'line',
      data:{
        labels: t.chart_timestamps,
        datasets: [
          {label:'Raw', data:t.chart_latencies, borderColor:colors.line, backgroundColor:colors.fill, borderWidth:0.8, fill:true, pointRadius:0, tension:0.1, order:2},
          {label:'Trend', data:t.chart_moving_avg, borderColor:colors.ma, borderWidth:2.5, fill:false, pointRadius:0, tension:0.4, order:1},
          {label:'Loss', data:lossPoints, borderColor:'transparent', pointRadius:5, pointBackgroundColor:'#ef4444', pointBorderColor:'#ef4444', showLine:false, order:0},
        ]
      },
      options:{
        responsive:true, maintainAspectRatio:false, animation:false,
        interaction:{mode:'index', intersect:false},
        plugins:{
          legend:{display:false},
          tooltip:{backgroundColor:'#1a1b24', titleColor:'#e8eaed', bodyColor:'#6b7280', borderColor:'#2a2b35', borderWidth:1,
            callbacks:{label:function(ctx){
              if(ctx.datasetIndex===2) return 'PACKET LOST';
              if(ctx.datasetIndex===1) return 'Trend: '+ctx.parsed.y+'ms';
              return 'Raw: '+ctx.parsed.y+'ms';
            }}
          }
        },
        scales:{
          x:{ticks:{color:'#3a3b45', maxTicksLimit:6, font:{size:10}}, grid:{color:'#1a1b24'}},
          y:{ticks:{color:'#3a3b45', font:{size:10}}, grid:{color:'#1a1b24'}, beginAtZero:true},
        }
      }
    });
  }
}

function buildIncidents(targets) {
  const all = [];
  targets.forEach(t => {
    (t.incidents||[]).forEach(inc => {
      let detail = '';
      if (inc.drops > 0) detail += inc.drops + ' dropped';
      if (inc.spikes > 0) detail += (detail?' + ':'')+inc.spikes + ' spikes';
      if (inc.max_lat > 0) detail += ' (peak '+Math.round(inc.max_lat)+'ms)';
      const type = inc.drops > 0 ? 'loss' : 'spike';
      all.push({start:inc.start, end:inc.end, target:inc.target, type, detail, samples:inc.samples});
    });
  });

  const card = document.getElementById('incidents-card');
  const list = document.getElementById('incident-list');

  if (all.length === 0) { card.style.display='none'; return; }
  card.style.display='block';

  // Most recent first, limit 25
  const recent = all.slice(-25).reverse();
  list.innerHTML = recent.map(inc => {
    const timeRange = inc.start === inc.end ? inc.start : inc.start+' - '+inc.end;
    return `<div class="incident">
      <span class="incident-time">${timeRange}</span>
      <span class="incident-badge ${inc.type}">${inc.type==='loss'?'DROP':'SPIKE'}</span>
      <span class="incident-target">${inc.target}</span>
      <span class="incident-detail">${inc.detail}</span>
    </div>`;
  }).join('');
}

// === Settings ===
function toggleSettings() {
  const overlay = document.getElementById('settings-overlay');
  const btn = document.getElementById('settings-cog-btn');
  const isOpen = overlay.classList.toggle('open');
  btn.classList.toggle('active', isOpen);
  if (isOpen) checkPassword();
}

async function checkPassword() {
  try {
    const res = await fetch('/api/settings/password/check');
    const data = await res.json();
    const el = document.getElementById('password-status');
    if (data.stored) {
      el.textContent = 'Stored';
      el.className = 'settings-status ok';
      fetchRouterStatus();
    } else {
      el.textContent = 'Not configured';
      el.className = 'settings-status none';
    }
  } catch(e) {
    document.getElementById('password-status').textContent = 'Error checking';
  }
}

async function savePassword() {
  const pw = document.getElementById('settings-password').value;
  if (!pw) return;
  try {
    const res = await fetch('/api/settings/password', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({password: pw})
    });
    const data = await res.json();
    const el = document.getElementById('password-status');
    if (data.success) {
      el.textContent = 'Stored';
      el.className = 'settings-status ok';
      document.getElementById('settings-password').value = '';
    } else {
      el.textContent = 'Save failed: ' + (data.error || 'unknown');
      el.className = 'settings-status none';
    }
  } catch(e) {
    document.getElementById('password-status').textContent = 'Save failed';
  }
}

async function testConnection() {
  const btn = document.getElementById('test-conn-btn');
  btn.textContent = 'Testing...';
  btn.disabled = true;
  try {
    const res = await fetch('/api/router/status');
    const data = await res.json();
    if (data.error) {
      document.getElementById('password-status').textContent = 'Failed: ' + data.error;
      document.getElementById('password-status').className = 'settings-status none';
    } else {
      document.getElementById('password-status').textContent = 'Connected';
      document.getElementById('password-status').className = 'settings-status ok';
      renderRouterStats(data);
    }
  } catch(e) {
    document.getElementById('password-status').textContent = 'Connection failed';
    document.getElementById('password-status').className = 'settings-status none';
  }
  btn.textContent = 'Test Connection';
  btn.disabled = false;
}

async function fetchRouterStatus() {
  const btn = document.getElementById('refresh-stats-btn');
  const status = document.getElementById('stats-status');
  btn.textContent = 'Loading...';
  btn.disabled = true;
  status.textContent = '';
  try {
    const res = await fetch('/api/router/status');
    const data = await res.json();
    if (data.error) {
      status.textContent = data.error;
      status.className = 'settings-status none';
    } else {
      status.textContent = 'Updated ' + new Date().toLocaleTimeString();
      status.className = 'settings-status ok';
      renderRouterStats(data);
    }
  } catch(e) {
    status.textContent = 'Failed to fetch';
    status.className = 'settings-status none';
  }
  btn.textContent = 'Refresh';
  btn.disabled = false;
}

function renderRouterStats(data) {
  const grid = document.getElementById('router-stats-grid');
  let html = '';
  const inet = data.internet || {};
  if (inet.wan_ip) html += '<dt>WAN IP</dt><dd>'+h(inet.wan_ip)+'</dd>';
  if (inet.uptime !== undefined) {
    const hrs = Math.floor(inet.uptime / 3600);
    const mins = Math.floor((inet.uptime % 3600) / 60);
    html += '<dt>Uptime</dt><dd>'+hrs+'h '+mins+'m</dd>';
  }
  if (inet.connect_type) html += '<dt>Connection</dt><dd>'+h(inet.connect_type)+'</dd>';
  if (inet.dns) html += '<dt>DNS</dt><dd>'+h(inet.dns)+'</dd>';
  const bandLabels = {wireless_2g:'2.4GHz', wireless_5g:'5GHz', wireless_6g:'6GHz'};
  for (const band of ['wireless_2g','wireless_5g','wireless_6g']) {
    const w = data[band];
    if (!w) continue;
    const lbl = bandLabels[band];
    if (w.ssid) html += '<dt>'+lbl+' SSID</dt><dd>'+h(w.ssid)+'</dd>';
    if (w.current_channel) html += '<dt>'+lbl+' Ch</dt><dd>'+h(w.current_channel)+' ('+h(w.htmode||'')+'MHz)</dd>';
  }
  const dev = data.device || {};
  if (dev.model) html += '<dt>Model</dt><dd>'+h(dev.model)+'</dd>';
  if (dev.firmware) html += '<dt>Firmware</dt><dd>'+h(dev.firmware)+'</dd>';
  if (dev.hardware) html += '<dt>Hardware</dt><dd>'+h(dev.hardware)+'</dd>';
  if (!html) html = '<dt>Status</dt><dd>No data returned</dd>';
  grid.innerHTML = html;
}

function exportData(format) {
  document.getElementById('export-window').textContent = currentMinutes;
  window.location.href = '/api/export/' + format + '?minutes=' + currentMinutes;
}

fetchData();
setInterval(fetchData, 10000);
</script>
</body>
</html>""";


def main():
    PID_FILE.write_text(str(os.getpid()))

    def cleanup(sig, frame):
        PID_FILE.unlink(missing_ok=True)
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    server = http.server.HTTPServer(("127.0.0.1", PORT), DashboardHandler)
    print(f"NotMyRouter dashboard: http://localhost:{PORT}")
    print(f"Reading logs from {LOG_DIR}")
    print("Press Ctrl+C to stop")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        PID_FILE.unlink(missing_ok=True)
        server.server_close()


if __name__ == "__main__":
    main()
