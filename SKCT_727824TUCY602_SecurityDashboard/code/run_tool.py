# Name: Prithiveraj E | Roll No: 727824TUCY602
# student_name   : Prithiveraj E
# roll_number    : 727824TUCY602
# project_name   : Security Dashboard (SIEM Lite)
# date           : 2026-03-28

"""
Pipeline Stage 2 — Run Tool
- Runs SIEM analysis on all 3 test-case log files
- Calls log_parser, alert_engine, threat_classifier for each
- Saves individual JSON results per scenario
- Prints roll number + timestamp on execution
"""

import sys
import os
import json
import datetime

ROLL_NUMBER  = "727824TUCY602"
STUDENT_NAME = "Prithiveraj E"

print(f"[RUN] Roll No: {ROLL_NUMBER} | Timestamp: {datetime.datetime.now()}")

# Ensure we can import helper_modules from the code/ directory
sys.path.insert(0, os.path.dirname(__file__))
from helper_modules.log_parser import parse_log_file
from helper_modules.alert_engine import AlertEngine
from helper_modules.threat_classifier import classify_threat

SCENARIOS = {
    "TC1_BruteForce" : "logs/tc1_brute_force.log",
    "TC2_PortScan"   : "logs/tc2_port_scan.log",
    "TC3_Clean"      : "logs/tc3_clean.log",
}

def run_scenario(name: str, log_path: str) -> dict:
    print(f"\n  [>>] Scenario: {name}")
    print(f"       Log file: {log_path}")

    events = parse_log_file(log_path)
    engine = AlertEngine(brute_threshold=5, portscan_threshold=15)
    alerts = []

    for event in events:
        threat = classify_threat(event)
        event["threat_type"] = threat
        alert = engine.evaluate(event)
        if alert:
            alerts.append(alert)

    result = {
        "scenario"    : name,
        "roll_number" : ROLL_NUMBER,
        "log_file"    : log_path,
        "run_time"    : datetime.datetime.now().isoformat(),
        "events_total": len(events),
        "alerts_total": len(alerts),
        "alerts"      : alerts,
        "engine_summary": engine.summary(),
    }

    print(f"       Events  : {len(events)}")
    print(f"       Alerts  : {len(alerts)}")
    for a in alerts[:3]:   # preview first 3
        print(f"         ⚠ [{a['severity']}] {a['threat_type']} — {a['source_ip']}")
    if len(alerts) > 3:
        print(f"         ... and {len(alerts)-3} more alert(s)")

    return result

def main():
    print(f"\n{'='*55}")
    print(f"  STAGE 2 — Run SIEM Tool on All Test Cases")
    print(f"  Student : {STUDENT_NAME}  |  Roll: {ROLL_NUMBER}")
    print(f"  Time    : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*55}")

    os.makedirs("outputs", exist_ok=True)
    all_results = []

    for name, log_path in SCENARIOS.items():
        if not os.path.exists(log_path):
            print(f"  [!] Log not found: {log_path}. Run setup_lab.py first.")
            continue
        result = run_scenario(name, log_path)
        all_results.append(result)

        # Save per-scenario JSON
        out_file = f"outputs/{name}_result.json"
        with open(out_file, "w") as f:
            json.dump(result, f, indent=2)
        print(f"       Saved  → {out_file}")

    # Save combined
    combined_path = "outputs/all_results.json"
    with open(combined_path, "w") as f:
        json.dump(all_results, f, indent=2)
    print(f"\n[✓] All results saved → {combined_path}")
    print(f"[✓] Stage 2 complete! | Roll No: {ROLL_NUMBER} | {datetime.datetime.now()}")

if __name__ == "__main__":
    main()
