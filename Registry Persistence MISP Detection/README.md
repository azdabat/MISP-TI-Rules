# Registry Persistence & CTI-Enriched Detection Pack  
**Platform:** Microsoft Defender for Endpoint / Sentinel  
**Author:** Ala Dabat  
**Type:** Adaptive Detection + Native Hunts + MISP Intelligence  
**Scope:** Post-Exploitation, Supply-Chain Intrusions, APT Persistence  
**Coverage:** Windows Registry Persistence • COM Hijack • IFEO • LSA/SSP • AppInit_DLLs • Services  
**MITRE:** TA0003 (Persistence) • TA0002 (Execution) • TA0005 (Defense Evasion)
<kbd>
</kbd>

---

**NOTE: Rule created over months of alert detections and IR cases**

## Overview

This pack provides **high-fidelity, low-noise detection analytics** for registry-based persistence and configuration abuse.  
It combines:

- **Core behavioural signals** (encoded commands, LOLBins, network indicators)  
- **Registry-based foothold vectors** used by APT groups and malware loaders  
- **Publisher trust checks**, SHA256 rarity, process lineage, user path analysis  
- Optional **MISP intelligence integration** (hash/domain/filename/campaign tags)  
- Weighted final risk scoring  
- **Auto-generated hunter directives** to drive investigation flow

These detections are engineered for real attacker behaviour, not generic telemetry.

---

# MISP-Enriched Registry Persistence Detection  
**Mode:** CTI Fusion + Behavioural Analysis  
**Purpose:** Identify registry persistence created by loaders, droppers, implants, supply-chain malware, and APT infrastructure.

---

## What This Detection Covers

| Category | Coverage | Notes |
|---------|---------:|-------|
| Run / RunOnce keys | 🟩 | Classic autoruns used by loaders and commodity malware |
| Winlogon Shell / Userinit hijack | 🟩 | Core foothold persistence |
| AppInit_DLLs | 🟩 | Global DLL injection (TrickBot, PlugX, QakBot) |
| Services persistence | 🟩 | Modified ImagePath values |
| IFEO debugger hijack | 🟩 | Redirects executables to malicious loaders |
| COM Hijacking (CLSID/InprocServer32) | 🟩 | High-value APT persistence |
| LSA/SSP credential modules | 🟩 | Credential theft with long-term foothold |
| User-writable EXE/DLL paths | 🟩 | AppData/ProgramData/Temp loaders |
| Registry-stored URLs/IP/C2 configs | 🟩 | Pulling commands/config from registry |
| Rare unsigned persistence binaries | 🟩 | Prevalence scoring |
| MISP Indicators (domains, SHA256, tags) | 🟩 | Severity uplift + context |
| Supply-chain persistence stages | 🟩 | Registry-based foothold post-install |

---

# Real-World Attack Coverage

## 3CX Supply Chain (2023)

| Component | Detected | Reason |
|----------|---------:|--------|
| Run key persistence | 🟩 | Autorun monitored |
| Loader DLL path in AppData | 🟩 | User-writable + suspicious file |
| Registry-stored config URLs | 🟩 | URL + domain regex |
| Sideloading stage | 🟥 | No registry modification at that stage |

---

## SolarWinds SUNBURST

| Component | Detected | Reason |
|----------|---------:|--------|
| Registry-stored obfuscated C2 | 🟩 | Base64 + URL regex |
| Service modifications | 🟩 | Services key coverage |
| DLL preload | 🟥 | Covered by DLL sideloading rule |

---

## NotPetya / M.E.Doc

| Component | Detected | Reason |
|----------|---------:|--------|
| Services-based persistence | 🟩 | Monitored key |
| Run key tooling (PowerShell) | 🟩 | Encoded commands detected |
| SMB lateral movement stage | 🟥 | Separate detection path |

---

## NTT Data Style Intrusion (2025 Simulation)

| Component | Detected | Reason |
|----------|---------:|--------|
| IFEO debugger override | 🟩 | Explicit path check |
| COM hijacking | 🟩 | CLSID/InProcServer32 analysis |
| Unsigned rare DLL/EXE | 🟩 | Prevalence scoring |
| Registry-hosted loader instructions | 🟩 | URL/Base64 patterns |
| Driver-stage persistence | 🟥 | Covered by driver hunt |

---

## F5 Appliance → Windows Pivot

| Component | Detected | Reason |
|----------|---------:|--------|
| Registry foothold dropped by pivot | 🟩 | Run/Policy keys |
| COM hijack persistence | 🟩 | CLSID coverage |
| SSP credential modules | 🟩 | LSA registry coverage |
| Appliance-only side | 🟥 | No registry writes |

---

# Known Gaps (By Design)

| Gap | Reason |
|------|--------|
| DLL sideloading | Not registry-based |
| Kernel-driver persistence | Requires kernel telemetry |
| SYSVOL/GPO-based persistence | Not endpoint-written |
| WMI Event Consumers | Not registry keys |
| Startup folder persistence | File-based |
| Linux/appliance persistence | Not Windows registry |

Pair this with:

- DLL Sideloading Hunt  
- BYOVD / Malicious Driver Hunt  
- OAuth Abuse Detection  
- Browser Extension Hunt  
- NTDS & Directory Extraction Hunt  
- SMB Lateral Movement Hunt  
- Suspicious Ports / C2 Jitter Hunts

---

# MISP Integration

Uses:

ThreatIntelligenceIndicator
Indicator // SHA256, domain, IP, filename
ConfidenceScore // Weighted into FinalScore
ThreatType
Tags // APT/campaign/TTP context
TLP

Risk Levels:

| Score | Level |
|-------|--------|
| ≥ 90 | CRITICAL |
| ≥ 70 | HIGH |
| < 70 | MEDIUM |

---

# Threat Hunter Directive (Auto-Generated)

Examples:

- **CRITICAL:** isolate host → memory acquisition → IOC block → MISP sighting  
- **HIGH:** validate autorun → verify signer → pivot to file/network  
- **MEDIUM:** review value → compare baseline → monitor recurrence  

Directives are context-aware and vary per detection.

---

# Rule Location

The full rule can be found under:
~~~
/Registry-Persistence
├── MISP-Enriched-Registry-Persistence.kql
└── Registry-Persistence-Native.kql
~~~

Native version removes all CTI references and uses pure behavioural logic.

---

# For Expansion

If required, the README can include:

- Entire CTI + Native detection suite  
- MITRE heatmap  
- Rule crosslinks  
- Architecture diagram  
- Threat hunting workflow  
- Data schema notes  
- CPU usage notes per rule

Just specify what you want added next.
