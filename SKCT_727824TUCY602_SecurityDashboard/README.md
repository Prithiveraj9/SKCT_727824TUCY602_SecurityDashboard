# 🛡️ SIEM Lite — Security Dashboard

| Field | Details |
|---|---|
| **Student** | Prithiveraj E |
| **Roll Number** | 727824TUCY602 |
| **Project Name** | Security Dashboard (SIEM Lite) |
| **Category** | Security Monitoring / Log Analysis |
| **GitHub Repo** | hacker-skct-727824TUCY602 |

---

## 📌 Tool Description

**SIEM Lite** is a lightweight Security Information and Event Management dashboard
built in Python. It parses syslog-style log files, detects threats using rule-based
analysis, classifies threats (Brute Force, Port Scan, Unauthorized Access), and
outputs severity-tagged alerts with a summary report.

---

## 🧰 Tools & Libraries

- Python 3.10+
- `pandas`, `matplotlib`, `rich`, `colorama`
- Kali Linux (VM) + Metasploitable2 (target)
- VirtualBox

---

## ⚙️ Lab Environment

- **Attacker**: Kali Linux VM (VirtualBox)
- **Target**: Metasploitable2 VM (isolated host-only network)
- All testing performed on isolated VMs — no external systems targeted.

---

## 🚀 Setup & Usage

### 1. Clone the repo
```bash
git clone https://github.com/[username]/hacker-skct-727824TUCY602
cd hacker-skct-727824TUCY602
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Run the full pipeline
```bash
# Stage 1 — Setup
python code/setup_lab.py

# Stage 2 — Run tool (all 3 test cases)
python code/run_tool.py

# Stage 3 — Analyze results
python code/analyze_results.py
```

### 4. Run a single test case directly
```bash
python code/tool_main.py brute_force   # TC1
python code/tool_main.py port_scan     # TC2
python code/tool_main.py clean         # TC3
```

---

## 🧪 Test Cases

| TC | Scenario | Expected Alert |
|---|---|---|
| TC1 | 10 failed SSH logins from same IP | CRITICAL — Brute Force Attack |
| TC2 | Connections to 20 unique ports | HIGH — Port Scan / Reconnaissance |
| TC3 | Normal authenticated logins only | No alerts — Traffic clean |

---

## 📁 Repository Structure

```
/code/
  tool_main.py          ← Core SIEM dashboard
  setup_lab.py          ← Pipeline Stage 1
  run_tool.py           ← Pipeline Stage 2
  analyze_results.py    ← Pipeline Stage 3
  helper_modules/
    log_parser.py
    alert_engine.py
    threat_classifier.py

/notebooks/
  demo.ipynb            ← Live demo with outputs

/screenshots/           ← 3+ tool-in-action screenshots
/report/
  report.pdf            ← 2-page project report

pipeline_727824TUCY602.yml
requirements.txt
README.md
submission_form.txt
```

---

## ⚠️ Ethical Considerations

All exploitation and testing was performed **exclusively on VMs owned by the student**
in an isolated VirtualBox network. No external or third-party systems were targeted.
