# student_name   : Prithiveraj E
# roll_number    : 727824TUCY602
# project_name   : Security Dashboard (SIEM Lite)
# date           : 2026-03-28

from collections import defaultdict
import datetime

ROLL_NUMBER = "727824TUCY602"

class AlertEngine:
    """
    Rule-based alert engine.
    Rules:
      R1 — SSH_FAIL count from same IP >= brute_threshold  → CRITICAL (Brute Force)
      R2 — FIREWALL_DROP unique ports from same IP >= portscan_threshold → HIGH (Port Scan)
      R3 — SSH_SUCCESS from a previously flagged brute-force IP → HIGH
    """

    def __init__(self, brute_threshold=5, portscan_threshold=15):
        self.brute_threshold    = brute_threshold
        self.portscan_threshold = portscan_threshold
        self._fail_count        = defaultdict(int)       # ip → fail count
        self._ports_seen        = defaultdict(set)       # ip → set of ports
        self._flagged_ips       = set()                  # brute-force flagged IPs
        self._issued_alerts     = []

    def evaluate(self, event: dict) -> dict | None:
        """
        Evaluate a single parsed event against all rules.
        Returns an alert dict if a rule fires, else None.
        """
        etype = event.get("event_type")
        ip    = event.get("source_ip", "unknown")
        port  = event.get("port", "?")

        # ── Rule 1: Brute Force Detection ────────────────────────────────────
        if etype == "SSH_FAIL":
            self._fail_count[ip] += 1
            if self._fail_count[ip] == self.brute_threshold:
                self._flagged_ips.add(ip)
                return self._make_alert(
                    severity   = "CRITICAL",
                    threat_type= "Brute Force Attack",
                    source_ip  = ip,
                    detail     = f"{self._fail_count[ip]} failed SSH attempts detected"
                )
            elif self._fail_count[ip] > self.brute_threshold:
                # Continue raising alerts after threshold
                return self._make_alert(
                    severity   = "CRITICAL",
                    threat_type= "Brute Force (Ongoing)",
                    source_ip  = ip,
                    detail     = f"Total failed attempts: {self._fail_count[ip]}"
                )

        # ── Rule 2: Port Scan Detection ───────────────────────────────────────
        if etype == "FIREWALL_DROP":
            self._ports_seen[ip].add(port)
            if len(self._ports_seen[ip]) == self.portscan_threshold:
                return self._make_alert(
                    severity   = "HIGH",
                    threat_type= "Port Scan / Reconnaissance",
                    source_ip  = ip,
                    detail     = f"Connections to {len(self._ports_seen[ip])} unique ports"
                )
            elif len(self._ports_seen[ip]) > self.portscan_threshold:
                return self._make_alert(
                    severity   = "HIGH",
                    threat_type= "Port Scan (Ongoing)",
                    source_ip  = ip,
                    detail     = f"Now scanning port {port} — total: {len(self._ports_seen[ip])}"
                )

        # ── Rule 3: Successful login from flagged IP ──────────────────────────
        if etype == "SSH_SUCCESS" and ip in self._flagged_ips:
            return self._make_alert(
                severity   = "HIGH",
                threat_type= "Unauthorized Access (Post-Brute)",
                source_ip  = ip,
                detail     = f"Login SUCCESS after brute-force from {ip}"
            )

        return None

    def _make_alert(self, severity, threat_type, source_ip, detail) -> dict:
        alert = {
            "timestamp"  : datetime.datetime.now().isoformat(),
            "severity"   : severity,
            "threat_type": threat_type,
            "source_ip"  : source_ip,
            "detail"     : detail,
            "roll_number": ROLL_NUMBER
        }
        self._issued_alerts.append(alert)
        return alert

    def summary(self) -> dict:
        return {
            "total_alerts" : len(self._issued_alerts),
            "brute_ips"    : list(self._flagged_ips),
            "scanned_ips"  : list(self._ports_seen.keys()),
        }
