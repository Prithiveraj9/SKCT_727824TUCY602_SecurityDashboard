# student_name   : Prithiveraj E
# roll_number    : 727824TUCY602
# project_name   : Security Dashboard (SIEM Lite)
# date           : 2026-03-28

import re
import datetime

ROLL_NUMBER = "727824TUCY602"

# ── Regex patterns ─────────────────────────────────────────────────────────────
SSH_FAIL    = re.compile(r"Failed password for (\S+) from ([\d.]+) port (\d+)")
SSH_SUCCESS = re.compile(r"Accepted password for (\S+) from ([\d.]+) port (\d+)")
PORT_SCAN   = re.compile(r"SRC=([\d.]+) DST=([\d.]+) PROTO=(\S+) SPT=(\d+) DPT=(\d+)")

def parse_log_file(filepath: str) -> list:
    """
    Parse a syslog-style log file and return a list of structured event dicts.
    Handles SSH failures, SSH successes, and kernel firewall/iptables lines.
    """
    events = []
    try:
        with open(filepath, "r") as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"[!] Log file not found: {filepath}")
        return events

    for lineno, raw in enumerate(lines, start=1):
        raw = raw.strip()
        if not raw:
            continue

        event = {
            "line_no"    : lineno,
            "raw"        : raw,
            "timestamp"  : _extract_timestamp(raw),
            "source_ip"  : "unknown",
            "event_type" : "UNKNOWN",
            "user"       : None,
            "port"       : None,
            "severity"   : "LOW",
        }

        m = SSH_FAIL.search(raw)
        if m:
            event["event_type"] = "SSH_FAIL"
            event["user"]       = m.group(1)
            event["source_ip"]  = m.group(2)
            event["port"]       = m.group(3)
            event["severity"]   = "MEDIUM"
            events.append(event)
            continue

        m = SSH_SUCCESS.search(raw)
        if m:
            event["event_type"] = "SSH_SUCCESS"
            event["user"]       = m.group(1)
            event["source_ip"]  = m.group(2)
            event["port"]       = m.group(3)
            event["severity"]   = "LOW"
            events.append(event)
            continue

        m = PORT_SCAN.search(raw)
        if m:
            event["event_type"] = "FIREWALL_DROP"
            event["source_ip"]  = m.group(1)
            event["port"]       = m.group(5)   # destination port
            event["severity"]   = "MEDIUM"
            events.append(event)
            continue

        # Generic — keep for completeness
        events.append(event)

    print(f"[LogParser] Parsed {len(events)} events from '{filepath}'  | Roll: {ROLL_NUMBER}")
    return events

def _extract_timestamp(line: str) -> str:
    """Try to extract a syslog timestamp from the start of a log line."""
    pattern = re.compile(r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})')
    m = pattern.match(line)
    if m:
        return m.group(1)
    return datetime.datetime.now().strftime("%b %d %H:%M:%S")
