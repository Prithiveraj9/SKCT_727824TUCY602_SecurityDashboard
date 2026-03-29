# student_name   : Prithiveraj E
# roll_number    : 727824TUCY602
# project_name   : Security Dashboard (SIEM Lite)
# date           : 2026-03-28

ROLL_NUMBER = "727824TUCY602"

# ── Threat label map ───────────────────────────────────────────────────────────
_EVENT_TO_THREAT = {
    "SSH_FAIL"      : "Credential Attack",
    "SSH_SUCCESS"   : "Normal Login",
    "FIREWALL_DROP" : "Reconnaissance",
    "UNKNOWN"       : "Unclassified",
}

# Known malicious IPs (demo list — extend as needed)
_KNOWN_BAD_IPS = {
    "192.168.1.50",   # simulated attacker (TC1)
    "192.168.1.99",   # simulated scanner  (TC2)
    "10.0.0.254",
}

def classify_threat(event: dict) -> str:
    """
    Classify an event into a human-readable threat category.
    Factors: event_type, source_ip reputation, port number.
    Returns a threat label string.
    """
    etype     = event.get("event_type", "UNKNOWN")
    source_ip = event.get("source_ip", "")
    port      = str(event.get("port", ""))

    # Known bad IP escalation
    if source_ip in _KNOWN_BAD_IPS:
        if etype == "SSH_FAIL":
            return "Brute Force Attempt"
        if etype == "FIREWALL_DROP":
            return "Malicious Reconnaissance"
        if etype == "SSH_SUCCESS":
            return "Unauthorized Access"

    # Sensitive port heuristics
    if port in {"22", "23", "3389", "445", "135"}:
        if etype == "SSH_FAIL":
            return "Credential Attack on Sensitive Port"
        if etype == "FIREWALL_DROP":
            return "Probe on Sensitive Port"

    # Default mapping
    return _EVENT_TO_THREAT.get(etype, "Unclassified")


def severity_from_threat(threat: str) -> str:
    """Return a default severity level for a given threat label."""
    mapping = {
        "Brute Force Attempt"               : "CRITICAL",
        "Malicious Reconnaissance"          : "HIGH",
        "Unauthorized Access"               : "HIGH",
        "Credential Attack on Sensitive Port": "HIGH",
        "Probe on Sensitive Port"           : "MEDIUM",
        "Credential Attack"                 : "MEDIUM",
        "Reconnaissance"                    : "MEDIUM",
        "Normal Login"                      : "LOW",
        "Unclassified"                      : "LOW",
    }
    return mapping.get(threat, "LOW")
