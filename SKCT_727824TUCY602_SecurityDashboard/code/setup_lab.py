# Name: Prithiveraj E | Roll No: 727824TUCY602
# student_name   : Prithiveraj E
# roll_number    : 727824TUCY602
# project_name   : Security Dashboard (SIEM Lite)
# date           : 2026-03-28

"""
Pipeline Stage 1 — Lab Setup
- Creates required folders
- Generates sample log files for all 3 test scenarios
- Verifies Python dependencies
- Prints roll number + timestamp on execution
"""

import os
import sys
import datetime
import subprocess

ROLL_NUMBER  = "727824TUCY602"
STUDENT_NAME = "Prithiveraj E"

print(f"[SETUP] Roll No: {ROLL_NUMBER} | Timestamp: {datetime.datetime.now()}")

REQUIRED_DIRS = ["logs", "outputs", "screenshots"]
REQUIRED_PKGS = ["pandas", "matplotlib", "colorama", "rich"]

def create_directories():
    for d in REQUIRED_DIRS:
        os.makedirs(d, exist_ok=True)
        print(f"  [✓] Directory ready: {d}/")

def check_dependencies():
    print("\n[*] Checking Python dependencies...")
    missing = []
    for pkg in REQUIRED_PKGS:
        try:
            __import__(pkg)
            print(f"  [✓] {pkg} is installed")
        except ImportError:
            print(f"  [!] {pkg} NOT found — installing...")
            missing.append(pkg)
    if missing:
        subprocess.check_call([sys.executable, "-m", "pip", "install", *missing, "-q"])
        print(f"  [✓] Installed missing packages: {missing}")

def generate_scenario_logs():
    """Write 3 separate scenario log files for the 3 test cases."""
    import re

    base = datetime.datetime.now()

    # TC1 — Brute Force
    lines_tc1 = []
    for i in range(10):
        t = (base + datetime.timedelta(seconds=i*5)).strftime("%b %d %H:%M:%S")
        lines_tc1.append(f"{t} server1 sshd[1234]: Failed password for root from 192.168.1.50 port 22 ssh2")
    with open("logs/tc1_brute_force.log", "w") as f:
        f.write("\n".join(lines_tc1))
    print("  [✓] TC1 log created: logs/tc1_brute_force.log")

    # TC2 — Port Scan
    lines_tc2 = []
    for port in range(1, 21):
        t = (base + datetime.timedelta(milliseconds=port*100)).strftime("%b %d %H:%M:%S")
        lines_tc2.append(
            f"{t} server1 kernel: IN= OUT=eth0 SRC=192.168.1.99 DST=10.0.0.2 "
            f"PROTO=TCP SPT={port+1024} DPT={port} WINDOW=65535"
        )
    with open("logs/tc2_port_scan.log", "w") as f:
        f.write("\n".join(lines_tc2))
    print("  [✓] TC2 log created: logs/tc2_port_scan.log")

    # TC3 — Clean / Normal traffic
    lines_tc3 = []
    for i in range(5):
        t = (base + datetime.timedelta(minutes=i)).strftime("%b %d %H:%M:%S")
        lines_tc3.append(f"{t} server1 sshd[1234]: Accepted password for user{i} from 10.0.0.{i+1} port 22 ssh2")
    with open("logs/tc3_clean.log", "w") as f:
        f.write("\n".join(lines_tc3))
    print("  [✓] TC3 log created: logs/tc3_clean.log")

    # Default log (used by run_tool.py if no arg)
    with open("logs/sample.log", "w") as f:
        f.write("\n".join(lines_tc1))
    print("  [✓] Default log created: logs/sample.log")

def main():
    print(f"\n{'='*55}")
    print(f"  STAGE 1 — Lab Setup")
    print(f"  Student : {STUDENT_NAME}  |  Roll: {ROLL_NUMBER}")
    print(f"  Time    : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*55}")

    print("\n[*] Creating project directories...")
    create_directories()

    check_dependencies()

    print("\n[*] Generating scenario log files...")
    generate_scenario_logs()

    print(f"\n[✓] Lab setup complete! | Roll No: {ROLL_NUMBER} | {datetime.datetime.now()}")

if __name__ == "__main__":
    main()
