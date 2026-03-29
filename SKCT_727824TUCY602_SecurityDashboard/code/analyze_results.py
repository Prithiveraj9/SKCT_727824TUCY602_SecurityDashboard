# Name: Prithiveraj E | Roll No: 727824TUCY602
# student_name   : Prithiveraj E
# roll_number    : 727824TUCY602
# project_name   : Security Dashboard (SIEM Lite)
# date           : 2026-03-28

"""
Pipeline Stage 3 — Analyze Results
- Reads outputs/all_results.json produced by run_tool.py
- Prints a formatted summary table of all test cases
- Counts alerts by severity across scenarios
- Saves a plain-text analysis report
- Prints roll number + timestamp on execution
"""

import json
import os
import datetime
from collections import Counter

ROLL_NUMBER  = "727824TUCY602"
STUDENT_NAME = "Prithiveraj E"

print(f"[ANALYZE] Roll No: {ROLL_NUMBER} | Timestamp: {datetime.datetime.now()}")

INPUT_FILE   = "outputs/all_results.json"
REPORT_FILE  = "outputs/analysis_report.txt"

def load_results() -> list:
    if not os.path.exists(INPUT_FILE):
        print(f"[!] Input file not found: {INPUT_FILE}. Run run_tool.py first.")
        return []
    with open(INPUT_FILE, "r") as f:
        return json.load(f)

def print_summary_table(results: list):
    print(f"\n{'─'*70}")
    print(f"  {'SCENARIO':<25} {'EVENTS':>8} {'ALERTS':>8}  FINDINGS")
    print(f"  {'─'*23}  {'─'*6}  {'─'*6}  {'─'*28}")
    for r in results:
        finding = "No threats detected"
        if r["alerts"]:
            # Highest severity alert
            sev_order = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}
            top = sorted(r["alerts"], key=lambda a: sev_order.get(a["severity"],9))[0]
            finding = f"[{top['severity']}] {top['threat_type']}"
        print(f"  {r['scenario']:<25} {r['events_total']:>8} {r['alerts_total']:>8}  {finding}")
    print(f"{'─'*70}")

def severity_breakdown(results: list) -> Counter:
    counter = Counter()
    for r in results:
        for a in r["alerts"]:
            counter[a["severity"]] += 1
    return counter

def save_report(results: list):
    lines = []
    lines.append("=" * 65)
    lines.append(f"  SIEM LITE — Analysis Report")
    lines.append(f"  Student    : {STUDENT_NAME}")
    lines.append(f"  Roll No    : {ROLL_NUMBER}")
    lines.append(f"  Generated  : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("=" * 65)
    lines.append("")

    lines.append("TEST CASE SUMMARY")
    lines.append(f"{'Scenario':<25} {'Events':>8} {'Alerts':>8}  Top Finding")
    lines.append("-" * 65)

    sev_order = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}
    for r in results:
        finding = "No threats detected"
        if r["alerts"]:
            top = sorted(r["alerts"], key=lambda a: sev_order.get(a["severity"],9))[0]
            finding = f"[{top['severity']}] {top['threat_type']} from {top['source_ip']}"
        lines.append(f"{r['scenario']:<25} {r['events_total']:>8} {r['alerts_total']:>8}  {finding}")

    lines.append("")
    lines.append("SEVERITY BREAKDOWN ACROSS ALL TEST CASES")
    breakdown = severity_breakdown(results)
    for sev in ["CRITICAL","HIGH","MEDIUM","LOW"]:
        count = breakdown.get(sev, 0)
        bar = "█" * count
        lines.append(f"  {sev:<10}: {count:>3}  {bar}")

    lines.append("")
    lines.append("CONCLUSIONS")
    total_alerts = sum(r["alerts_total"] for r in results)
    lines.append(f"  Total events  analysed : {sum(r['events_total'] for r in results)}")
    lines.append(f"  Total alerts  raised   : {total_alerts}")
    if breakdown.get("CRITICAL", 0):
        lines.append("  !! CRITICAL threats detected — immediate investigation required.")
    if breakdown.get("HIGH", 0):
        lines.append("  !  HIGH severity events detected — review firewall and access logs.")
    if total_alerts == 0:
        lines.append("  [OK] All traffic appears normal. No active threats identified.")

    lines.append("")
    lines.append("=" * 65)

    os.makedirs("outputs", exist_ok=True)
    with open(REPORT_FILE, "w") as f:
        f.write("\n".join(lines))
    print(f"\n[+] Analysis report saved → {REPORT_FILE}")

def main():
    print(f"\n{'='*55}")
    print(f"  STAGE 3 — Analyze Results")
    print(f"  Student : {STUDENT_NAME}  |  Roll: {ROLL_NUMBER}")
    print(f"  Time    : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*55}")

    results = load_results()
    if not results:
        return

    print_summary_table(results)

    breakdown = severity_breakdown(results)
    print("\n[*] Severity Breakdown:")
    for sev in ["CRITICAL","HIGH","MEDIUM","LOW"]:
        count = breakdown.get(sev, 0)
        bar   = "█" * count
        print(f"    {sev:<10}: {count:>3}  {bar}")

    save_report(results)
    print(f"\n[✓] Analysis complete! | Roll No: {ROLL_NUMBER} | {datetime.datetime.now()}")

if __name__ == "__main__":
    main()
