# 🛡️ Automated SOC Alert Triage & Incident Response Platform

An end-to-end, rule-based Security Operations Center (SOC) platform designed to ingest Wazuh security alerts, reduce alert fatigue through contextual analysis and incident aggregation, prioritize incidents using deterministic risk scoring, enrich alerts with MITRE ATT&CK and Threat Intelligence context, and support automated or analyst-driven response.

The project focuses on **transparent, explainable SOC automation without Machine Learning**.

---

## 📌 Project Overview

Tier-1 SOC analysts often face large volumes of security alerts, including repeated events, low-severity activity, and alerts that require additional context before escalation.

This project implements a lightweight SOC pipeline that transforms raw Wazuh alerts into **correlated, prioritized security incidents**.

Instead of treating every alert independently, the platform:

* Aggregates related alerts within time windows
* Reduces duplicate alert noise
* Applies trusted IP/user context
* Correlates repeated authentication events
* Calculates a deterministic risk score
* Maps detections to MITRE ATT&CK
* Enriches events with Threat Intelligence context
* Selects a context-aware response
* Stores incidents for investigation
* Sends important incidents through Telegram
* Visualizes incidents through a custom Streamlit SOC Dashboard

---

# 🏗️ Architecture

```text
┌─────────────────────────────────────────────────────────┐
│              Attack / Suspicious Activity               │
│       SSH Brute Force • Nmap • Suspicious Commands      │
└───────────────────────────┬─────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────┐
│                    System Telemetry                     │
│       auth.log • syslog • journald • command logs       │
└───────────────────────────┬─────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────┐
│                 Wazuh Detection Engine                  │
│            Custom Rules + Security Monitoring            │
└───────────────────────────┬─────────────────────────────┘
                            │
                            ▼
              /var/ossec/logs/alerts/alerts.json
                            │
                            ▼
┌─────────────────────────────────────────────────────────┐
│              Python SOC Triage Engine                   │
│                                                         │
│  • Alert Parsing                                        │
│  • Whitelist / Context Checks                           │
│  • Sliding Time-Window Correlation                      │
│  • Alert Deduplication                                  │
│  • Incident Aggregation                                 │
│  • Deterministic Risk Scoring                           │
│  • MITRE ATT&CK Mapping                                 │
│  • Threat Intelligence Enrichment                       │
│  • Context-Aware Response Selection                     │
└───────────────────────────┬─────────────────────────────┘
                            │
                ┌───────────┴───────────┐
                ▼                       ▼
       ┌────────────────┐      ┌────────────────────┐
       │ Automated       │      │ Analyst Investigation│
       │ Response        │      │                    │
       │                 │      │ • Review           │
       │ IP Block        │      │ • Investigate      │
       │ / Containment   │      │ • Contain          │
       └───────┬────────┘      └─────────┬──────────┘
               │                         │
               └────────────┬────────────┘
                            ▼
                  ┌──────────────────┐
                  │ SQLite Database  │
                  │ soc_incidents.db │
                  └────────┬─────────┘
                           │
                ┌──────────┴──────────┐
                ▼                     ▼
       ┌────────────────┐    ┌────────────────────┐
       │ Telegram       │    │ Streamlit SOC      │
       │ Notifications  │    │ Investigation      │
       │                │    │ Dashboard          │
       └────────────────┘    └────────────────────┘
```

---

# 🔍 Detection & Triage Workflow

The platform separates **detection** from **triage**.

### Wazuh

Wazuh is responsible for detecting suspicious activity and generating raw security alerts based on configured detection rules.

### Python Triage Engine

The custom Python engine processes the raw alerts and adds context that a single detection rule cannot provide.

For example:

```text
1 failed SSH login
        ↓
Low Risk / Log Only

5+ failed SSH logins
within a short time window
        ↓
Suspicious / Medium

Repeated failed logins
+ high event velocity
+ suspicious context
        ↓
True Positive / High Risk
        ↓
Containment / Analyst Escalation
```

This allows the platform to aggregate multiple low-level events into a single meaningful security incident.

---

# 🧠 Core Features

## 1. Stateful Alert Aggregation

Repeated alerts from the same source are grouped using sliding time windows.

Example:

```text
16 SSH authentication alerts
          ↓
1 correlated incident
```

This reduces alert duplication and makes the resulting incident easier for an analyst to investigate.

---

## 2. Alert Deduplication

Instead of displaying every repeated Wazuh alert as a separate incident, related events are consolidated.

Example:

```text
Raw Alerts:        18
Aggregated Incidents: 2
```

For this test run:

```text
Alert Reduction = (18 - 2) / 18 × 100
               = 88.9%
```

> This metric represents **alert aggregation/reduction**, not a measured false-positive reduction rate.

---

## 3. Context-Aware Triage

The engine evaluates additional context such as:

* Source IP
* Username
* Trusted IPs
* Trusted users
* Event frequency
* Time windows
* Alert severity
* Related events
* Available network context

Incidents are classified as:

```text
BENIGN
SUSPICIOUS
TRUE_POSITIVE
```

---

## 4. Deterministic Risk Scoring

Every incident receives a transparent risk score from:

```text
0 – 100
```

Risk levels:

|  Score | Severity |
| -----: | -------- |
|   0–30 | LOW      |
|  31–60 | MEDIUM   |
|  61–80 | HIGH     |
| 81–100 | CRITICAL |

The scoring logic is deterministic and explainable.

No Machine Learning is used.

---

## 5. MITRE ATT&CK Mapping

Detected behaviors are mapped to MITRE ATT&CK techniques.

Examples:

| Detection                       | MITRE ATT&CK |
| ------------------------------- | ------------ |
| SSH Brute Force                 | T1110.001    |
| Network Service Scanning        | T1046        |
| Ingress Tool Transfer           | T1105        |
| Obfuscated Files or Information | T1027        |

This provides an additional layer of context for SOC investigation and reporting.

---

## 6. Threat Intelligence Context

The platform can enrich incidents with Threat Intelligence information.

The system also recognizes local/private network addresses and avoids treating RFC1918 addresses as public Internet reputation indicators.

Example:

```text
Source IP: 192.168.1.200
Threat Intel Context:
RFC1918 Private Range / Local Subnet
```

External Threat Intelligence such as VirusTotal can be used when applicable and available.

The core triage pipeline does not depend entirely on external API availability.

---

# 🤖 Context-Aware Response

The response is selected based on the available context rather than blindly executing the same action for every alert.

### Example: Remote Source IP

```text
SSH Brute Force
        ↓
Source IP identified
        ↓
High Risk
        ↓
Eligible for IP containment
        ↓
Auto-Block / Containment
```

### Example: Host-Level Event

```text
Suspicious local activity
        ↓
No source IP available
        ↓
Host-Level Investigation
        ↓
Analyst Review / Host Audit
```

This prevents actions such as blocking an IP when no valid source IP is available.

> Automated containment is limited to predefined scenarios and should be treated as a controlled demonstration rather than unrestricted production automation.

---

# 📱 Telegram SOC Notifications

Important incidents can be sent to a Telegram bot for immediate analyst notification.

Example:

```text
🚨 SOC INCIDENT

Incident: INC-2026-001
Attack: SSH Brute Force

Source IP: 192.168.1.200
Events: 16
Risk Score: 74/100
Severity: HIGH

MITRE: T1110.001

Classification:
TRUE_POSITIVE

Action:
BLOCK_SOURCE_IP_AND_ISOLATE

Status:
QUEUED_FOR_AUTO_RESPONSE
```

Telegram acts as the **real-time notification channel**, while the Streamlit dashboard provides the broader investigation view.

---

# 🖥️ SOC Investigation Dashboard

The project includes a custom **Streamlit SOC Dashboard**.

The dashboard is designed as the analyst-facing investigation console rather than relying on the default Wazuh visualization layer.

Planned dashboard metrics include:

```text
┌─────────────────────────────────────────────┐
│             MINI SOC DASHBOARD              │
├────────────┬────────────┬───────────────────┤
│ Raw Alerts │ Incidents  │ Alert Reduction   │
│     18     │     2      │      88.9%        │
├────────────┴────────────┴───────────────────┤
│                                             │
│             Risk Distribution               │
│                                             │
├─────────────────────────────────────────────┤
│ Recent Incidents                            │
│                                             │
│ INC-001  SSH Brute Force       HIGH         │
│ INC-002  Suspicious Execution  HIGH         │
│                                             │
├─────────────────────────────────────────────┤
│ Incident Details                            │
│                                             │
│ Source IP • Evidence • MITRE • Risk         │
│ Classification • Response • Status          │
└─────────────────────────────────────────────┘
```

The dashboard will read the persisted incident data from SQLite.

---

# 🧪 Attack Scenarios

The project uses controlled attack simulations to generate detectable security events.

| Scenario                      | Example Activity                   | MITRE ATT&CK      |
| ----------------------------- | ---------------------------------- | ----------------- |
| SSH Brute Force               | Repeated failed SSH authentication | T1110.001         |
| Network Scanning              | Nmap scan                          | T1046             |
| Suspicious Command Execution  | Obfuscated command patterns        | T1027             |
| Suspicious Download           | Tool/file transfer activity        | T1105             |
| Privilege Escalation Activity | Suspicious sudo/su usage           | Context dependent |

All attack simulations are performed in a controlled lab environment.

---

# 📊 Current Test Results

Latest local test run:

```text
Raw Wazuh Alerts Ingested : 18
Aggregated Incidents      : 2
Alert Reduction           : 88.9%
```

### Incident 1 — SSH Brute Force

```text
Incident ID       : INC-2026-001
Events Aggregated : 16
Source IP         : 192.168.1.200
MITRE             : T1110.001
Risk Score        : 74/100
Severity          : HIGH
Classification    : TRUE_POSITIVE
```

### Incident 2 — Suspicious Download / Execution

```text
Incident ID       : INC-2026-002
Events Aggregated : 2
Source IP         : Unknown
MITRE             : T1105
Risk Score        : 70/100
Severity          : HIGH
Classification    : TRUE_POSITIVE
Response          : Analyst Investigation
```

---

# 🛠️ Technology Stack

| Component             | Technology                 | Purpose                             |
| --------------------- | -------------------------- | ----------------------------------- |
| Operating Environment | Kali Linux / WSL           | SOC lab environment                 |
| Detection             | Wazuh                      | Log monitoring and detection        |
| Automation            | Python 3                   | Triage and response logic           |
| Database              | SQLite3                    | Incident persistence                |
| Threat Intelligence   | VirusTotal / Local Context | IP and event enrichment             |
| Notifications         | Telegram Bot API           | Real-time incident alerts           |
| Dashboard             | Streamlit                  | SOC investigation interface         |
| Data Processing       | Python / Pandas            | Incident analysis and visualization |
| ATT&CK Framework      | MITRE ATT&CK               | Attack technique mapping            |

---

# 📁 Repository Structure

```text
Automated-SOC-Triage-Platform/
│
├── triage_engine.py
├── dashboard.py
├── simulate_attacks.sh
├── config.example.json
├── requirements.txt
├── README.md
│
├── rules/
│   └── local_rules.xml
│
└── data/
    └── .gitkeep
```

> Sensitive configuration such as Telegram tokens and API keys must never be committed to GitHub.

---

# ⚙️ Installation & Usage

## 1. Clone the Repository

```bash
git clone https://github.com/zeinabelsayed98/Automated-SOC-Triage-Platform.git
cd Automated-SOC-Triage-Platform
```

---

## 2. Configure the Environment

Create your local configuration:

```bash
cp config.example.json config.json
```

Add your local configuration values such as:

```text
Telegram Bot Token
Telegram Chat ID
Trusted IPs
Trusted Users
Triage Thresholds
```

**Never upload `config.json` if it contains secrets.**

---

## 3. Install Python Dependencies

```bash
pip3 install -r requirements.txt
```

---

## 4. Verify Wazuh Alerts

Confirm that Wazuh is generating alerts:

```bash
sudo tail -f /var/ossec/logs/alerts/alerts.json
```

---

## 5. Run the Triage Engine

```bash
python3 triage_engine.py
```

The engine will:

```text
Read Wazuh Alerts
       ↓
Parse Events
       ↓
Aggregate Related Alerts
       ↓
Apply Context
       ↓
Calculate Risk
       ↓
Classify Incidents
       ↓
Select Response
       ↓
Store / Dispatch Incident
```

---

## 6. Launch the SOC Dashboard

```bash
streamlit run dashboard.py
```

The Streamlit interface will provide the analyst-facing incident investigation console.

---

# 🔐 Security Considerations

This project is designed as a controlled cybersecurity laboratory and portfolio demonstration.

Important considerations:

* Automated blocking should be restricted to trusted test scenarios.
* Private/local IP addresses should not be treated as malicious Internet reputation data.
* API credentials must be stored outside source control.
* Telegram tokens must never be committed to GitHub.
* Attack simulations should only be performed against systems you own or are authorized to test.
* Automated response should remain bounded and auditable.

---

# 🚀 Future Improvements

Potential future improvements include:

* More advanced multi-event correlation
* Additional Wazuh detection rules
* Improved incident lifecycle management
* More Threat Intelligence providers
* Host isolation integrations
* Analyst feedback mechanisms
* PCAP/network telemetry integration
* Expanded SOC KPIs
* Role-based analyst access
* Integration with additional security tools

Machine Learning is intentionally outside the current project scope.

---

# 👩‍💻 Author

**Zainab Elsayed**

Cybersecurity Student | SOC Analyst | Network Security | Penetration Testing

---

## ⭐ Project Goal

The goal of this project is to demonstrate practical SOC engineering skills by building a complete pipeline from:

```text
Security Event
      ↓
Detection
      ↓
Triage
      ↓
Correlation
      ↓
Risk Assessment
      ↓
Threat Intelligence
      ↓
Response
      ↓
Notification
      ↓
Incident Management
      ↓
Analyst Dashboard
```

**Built as a hands-on Cybersecurity/SOC portfolio project.**
