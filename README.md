# 🧠 MISP-Integrated Threat Hunting & Supply Chain Detection Rules  
### *Author: Ala Dabat | Senior Threat & Detection Engineer*

---

## 🎯 Overview
This repository delivers **production-ready KQL threat-hunting rules** designed for **Microsoft Sentinel** and **Defender for Endpoint**, integrating **MISP Threat Intelligence** and **OpenCTI enrichment** to achieve high-fidelity detection of complex threats — from **supply-chain compromises** (SolarWinds, 3CX, NotPetya, NTT Data) to **OAuth consent abuse** and **driver/DLL sideloading persistence**.

Each rule is annotated with:
- Inline **MITRE ATT&CK tactics & techniques**
- **Hunter Directives** (actionable SOC guidance)
- **Adaptive scoring system**
- **TI correlation** via MISP/ThreatIntelligenceIndicator tables  
- Optional **VirusTotal lookup** and **dynamic allowlist joins**

---

## 🧩 Detection Methodology

| Layer | Description | Tools |
|-------|-------------|-------|
| **Native KQL Rules** | Detect anomalous behaviors (registry, ports, services, SMB) without TI reliance. | MDE, Sentinel |
| **MISP-Integrated Rules** | Join native detections with `ThreatIntelligenceIndicator` to enrich IPs, hashes, and domains with TI context. | MISP (TAXII 2.x) |
| **Adaptive Scoring** | Combines behavioral, temporal, and TI confidence signals to calculate final severity. | `(Detection*0.4)+(Intel*0.3)+(KillChain*0.2)+(Temporal*0.1)` |
| **Hunter Directives** | Inline analyst triage playbooks within query output. | All rules |
| **MITRE Mapping** | Aligns detections to ATT&CK tactics for IR & reporting. | Built into each rule |

---

## 🧠 Supply-Chain Attack Chains (ASCII)

### 🧱 SolarWinds (SUNBURST)  
