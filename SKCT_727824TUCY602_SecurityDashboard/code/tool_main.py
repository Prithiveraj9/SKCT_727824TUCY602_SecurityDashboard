# student_name   : Prithiveraj E
# roll_number    : 727824TUCY602
# project_name   : Security Dashboard (SIEM Lite)
# date           : 2026-03-28

import os
import json
import datetime
import re
from collections import defaultdict
from helper_modules.log_parser import parse_log_file
from helper_modules.alert_engine import AlertEngine
from helper_modules.threat_classifier import classify_threat

# ── Config ────────────────────────────────────────────────────────────────────
ROLL_NUMBER   = "727824TUCY602"
STUDENT_NAME  = "Prithiveraj E"
PROJECT_NAME  = "Security Dashboard (SIEM Lite)"
LOG_FILE      = "logs/sample.log"
OUTPUT_JSON   = "outputs/siem_results.json"
OUTPUT_CSV    = "outputs/siem_results.csv"
BRUTE_THRESHOLD = 5   # failed logins before CRITICAL alert
PORTSCAN_THRESHOLD = 15  # unique ports in short window before HIGH alert

# ── Banner ─────────────────────────────────────────────────────────────────────
def print_banner():
    print("=" * 65)
    print("   SIEM LITE — Security Information & Event Management Dashboard")
    print(f"   Student  : {STUDENT_NAME}")
    print(f"   Roll No  : {ROLL_NUMBER}")
    print(f"   Project  : {PROJECT_NAME}")
    print(f"   Run Time : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 65)

# ── Generate sample logs (for demo / test cases) ──────────────────────────────
def generate_sample_logs(scenario="brute_force"):
    os.makedirs("logs", exist_ok=True)
    lines = []
    base_time = datetime.datetime.now()

    if scenario == "brute_force":
        # TC1 – 10 failed SSH logins from same IP
        for i in range(10):
            t = (base_time + datetime.timedelta(seconds=i*5)).strftime("%b %d %H:%M:%S")
            lines.append(f"{t} server1 sshd[1234]: Failed password for root from 192.168.1.50 port 22 ssh2")
        lines.append(f"{base_time.strftime('%b %d %H:%M:%S')} server1 sshd[1234]: Accepted password for admin from 10.0.0.1 port 22 ssh2")

    elif scenario == "port_scan":
        # TC2 – connections to 20 different ports in rapid succession
        for port in range(1, 21):
            t = (base_time + datetime.timedelta(milliseconds=port*100)).strftime("%b %d %H:%M:%S")
            lines.append(f"{t} server1 kernel: IN= OUT=eth0 SRC=192.168.1.99 DST=10.0.0.2 PROTO=TCP SPT={port+1024} DPT={port} WINDOW=65535")

    elif scenario == "clean":
        # TC3 – normal traffic, no anomalies
        for i in range(5):
            t = (base_time + datetime.timedelta(minutes=i)).strftime("%b %d %H:%M:%S")
            lines.append(f"{t} server1 sshd[1234]: Accepted password for user{i} from 10.0.0.{i+1} port 22 ssh2")

    with open(LOG_FILE, "w") as f:
        f.write("\n".join(lines))
    print(f"[+] Sample log generated → {LOG_FILE}  (scenario: {scenario})")

# ── Core analysis ──────────────────────────────────────────────────────────────
def analyze_logs():
    events = parse_log_file(LOG_FILE)
    engine = AlertEngine(brute_threshold=BRUTE_THRESHOLD,
                         portscan_threshold=PORTSCAN_THRESHOLD)
    alerts = []

    for event in events:
        threat = classify_threat(event)
        event["threat_type"] = threat
        alert = engine.evaluate(event)
        if alert:
            alerts.append(alert)

    return events, alerts

# ── Print dashboard ────────────────────────────────────────────────────────────
def print_dashboard(events, alerts):
    severity_map = {"CRITICAL": "!!!", "HIGH": ">> ", "MEDIUM": "-- ", "LOW": "   "}
    print(f"\n{'─'*65}")
    print(f"  EVENTS PARSED : {len(events)}")
    print(f"  ALERTS RAISED : {len(alerts)}")
    print(f"{'─'*65}")

    if not alerts:
        print("  [OK]  No threats detected. Traffic looks clean.")
    else:
        print(f"  {'SEV':<10} {'THREAT':<25} {'SOURCE IP':<18} {'DETAIL'}")
        print(f"  {'-'*8}  {'-'*23}  {'-'*16}  {'-'*20}")
        for a in alerts:
            marker = severity_map.get(a["severity"], "   ")
            print(f"  {marker}{a['severity']:<8}  {a['threat_type']:<25}  {a['source_ip']:<18}  {a['detail']}")
    print(f"{'─'*65}\n")

# ── Save results ───────────────────────────────────────────────────────────────
def save_results(events, alerts):
    os.makedirs("outputs", exist_ok=True)
    result = {
        "run_by": STUDENT_NAME,
        "roll_number": ROLL_NUMBER,
        "timestamp": datetime.datetime.now().isoformat(),
        "total_events": len(events),
        "total_alerts": len(alerts),
        "alerts": alerts
    }
    with open(OUTPUT_JSON, "w") as f:
        json.dump(result, f, indent=2)

    # Simple CSV
    with open(OUTPUT_CSV, "w") as f:
        f.write("severity,threat_type,source_ip,detail\n")
        for a in alerts:
            f.write(f"{a['severity']},{a['threat_type']},{a['source_ip']},{a['detail']}\n")

    print(f"[+] Results saved → {OUTPUT_JSON}")
    print(f"[+] Results saved → {OUTPUT_CSV}")

# ── Main ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    scenario = sys.argv[1] if len(sys.argv) > 1 else "brute_force"

    print_banner()
    print(f"\n[*] Running Test Case Scenario : {scenario.upper()}")

    generate_sample_logs(scenario)
    events, alerts = analyze_logs()
    print_dashboard(events, alerts)
    save_results(events, alerts)

    print(f"[✓] SIEM scan complete. Roll No: {ROLL_NUMBER} | {datetime.datetime.now()}")
