# 🧠 MISP-TI Rules — Threat Hunting & CTI Integration  
_Adaptive KQL analytics for Microsoft Sentinel / MDE enriched with MISP and OpenCTI indicators._

---

## 📘 Overview

This repository extends my active **CTI hunts** collection with **MISP Threat Intelligence (TI)** and **OpenCTI enrichment**.  
All rules here are designed to detect and contextualize **supply-chain, lateral movement, credential, and persistence attacks**, using live threat-intel scoring and hunter directives.

Each rule:
- 🔍 Maps to **MITRE ATT&CK** tactics and techniques  
- 🧩 Correlates with **MISP IOC confidence** and **OpenCTI actor/campaign tags**  
- 🎯 Uses **adaptive scoring** to auto-prioritize detections  
- ⚙️ Is performance-optimized for Sentinel and MDE  

---

## 🧰 Rule Index

| File | Description | Focus | MITRE Tactics |
|------|--------------|--------|----------------|
| **01_DLL_Sideloading_Adaptive.kql** | Detects newly dropped DLLs (≤5 min) loaded by signed binaries | Supply-chain, EDR evasion | TA0005, TA0003 |
| **02_Registry_Persistence_MISP_Enriched.kql** | Registry autoruns & service key abuse with TI enrichment | Persistence, Defense Evasion | TA0003 |
| **03_Suspicious_Ports_with_External_CSV.kql** | External CSV feed of high-risk ports (C2 / proxy detection) | Command & Control | TA0011 |
| **04_SMB_Lateral_NotPetya_Style.kql** | Lateral SMB movement (WMIC/PsExec propagation) | Lateral Movement | TA0008 |
| **05_OAuth_Consent_Abuse.kql** | Rogue OAuth consents and Graph API abuse | Cloud Identity Compromise | TA0001, TA0005 |
| **06_Rogue_Endpoint_ZeroTrust.kql** | Detects un-onboarded or spoofed hosts | Discovery, Persistence | TA0007, TA0003 |
| **07_BEC_Clickthrough_Enriched.kql** | Users clicking through SafeLink rewrites | Social Engineering / BEC | TA0001 |
| **Kerberoasting-AS-REP-Golden-Ticket.kql** | Unified detection of Kerberoast, AS-REP & Golden Ticket | Credential Access | TA0006 |

---

## ⚙️ Adaptive Scoring Model

```kql
FinalScore = (DetectionSignal * 0.4)| Risk        | Threshold | Analyst Action             |
| ----------- | --------- | -------------------------- |
| 🔴 Critical | ≥ 90      | Immediate IR containment   |
| 🟠 High     | 75 – 89   | Escalate & triage          |
| 🟡 Medium   | 60 – 74   | Review context / correlate |
| 🟢 Low      | < 60      | Baseline monitor           |

flowchart LR
A[MISP] -->|TAXII 2.x| B[(ThreatIntelligenceIndicator)]
B --> C[KQL Rules]
C --> D[Adaptive Scoring]
D --> E[Sightings ↔ MISP]
E --> F[OpenCTI Graph Context]
F --> A

Data Flow

MISP → Sentinel via TAXII 2.x feeds → ThreatIntelligenceIndicator

Indicators: IP, domain, SHA256, mutex, registry, hostname

Tags: Galaxy → Threat Actor, Campaign, Malware Family, TLP

Confidence feeds into IntelConfidence (0–100 scale)

Sightings posted back to MISP → OpenCTI → visual link analysis

| Attack                    | Native Rules   | + MISP Integration | Key Detection              |
| ------------------------- | -------------- | ------------------ | -------------------------- |
| **SolarWinds (SUNBURST)** | 🟩🟨⬜ (40 %)   | 🟩🟩🟩⬜ (75 %)     | DLL Sideloading + Registry |
| **NotPetya (M.E.Doc)**    | 🟩🟩🟩⬜ (60 %) | 🟩🟩🟩🟨 (80 %)    | SMB Lateral + Ports        |
| **3CX Supply-Chain**      | 🟩🟨⬜ (35 %)   | 🟩🟩🟩⬜ (70 %)     | DLL Sideloading + C2 Match |
| **NTT Data (2025)**       | 🟩🟩🟨⬜ (55 %) | 🟩🟩🟩🟩 (90 %)    | OAuth Abuse + Rogue Hosts  |

| Rule           | Avg Runtime | Cost      | Optimisation Tip                      |
| -------------- | ----------- | --------- | ------------------------------------- |
| DLL / Registry | 20–40 s     | 🟡 Medium | Limit lookback ≤ 24 h                 |
| Ports Feed     | 10–15 s     | 🟢 Low    | Cache `externaldata()` → Watchlist    |
| SMB Lateral    | 25–50 s     | 🟡 Medium | Use `bin(1h)` aggregation             |
| OAuth Abuse    | ~10 s       | 🟢 Low    | Filter AuditLogs on Consent           |
| Kerberoast     | 30–90 s     | 🟠 High   | Materialize TI subset > 70 confidence |


| Tactic                   | Techniques                                        |
| ------------------------ | ------------------------------------------------- |
| **Initial Access**       | T1566 Phishing, T1078 Valid Accounts              |
| **Execution**            | T1059 Scripting, T1218 Signed Binary              |
| **Persistence**          | T1547 Registry Run Keys, T1053 Task Scheduler     |
| **Privilege Escalation** | T1068 Vulnerable Driver                           |
| **Defense Evasion**      | T1112 Modify Registry, T1218 Proxy Execution      |
| **Credential Access**    | T1558 Kerberoasting, T1003 LSASS                  |
| **Lateral Movement**     | T1021 SMB, T1077 RDP                              |
| **C2 / Exfiltration**    | T1071 App Layer Protocol, T1041 Data Exfiltration |



| Area          | Impact   | Mitigation                                         |                   |
| ------------- | -------- | -------------------------------------------------- | ----------------- |
| CPU / Memory  | 🟩🟩⬜⬜   | Apply filters early (`DeviceName startswith "DC"`) |                   |
| Query Time    | 🟩🟩🟨⬜  | 10–60 s typical                                    | Materialize joins |
| Sentinel Cost | 🟩🟩🟩⬜  | Low; native tables only                            |                   |
| Accuracy      | 🟩🟩🟩🟩 | High after MISP confidence integration             |                   |
