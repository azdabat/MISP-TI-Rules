# 🧬 MISP-Enriched Registry Persistence Detection  
**Platform:** MDE / Microsoft Sentinel  
**Author:** Ala Dabat  
**Type:** Adaptive, CTI-aware Detection (Registry Persistence + MISP Intelligence)  
**Supports:** Supply-Chain Attacks, APT Intrusions, Red-Team Tradecraft  
**Techniques:** TA0003 • TA0002 • TA0005  

---

## 📌 What This Detection Is

This analytic is an *adaptive*, *weighted*, *threat-intelligence-enriched* registry persistence detector, designed for:

- **Supply-chain malware** installing post-compromise persistence  
- **DLL & driver loader families** using Run/Services/IFEO keys  
- **APT “living registry” implants** (COM/LSA, AppInit_DLLs)  
- **Malware droppers** which modify autorun keys  
- **Backdoors leaving no file on disk** but storing commands/config in registry  

It uses:

- Behavioural signals (**encoded commands, LOLBins, network IOCs**)  
- **MISP indicators** (domains, hashes, filenames, kill-chain tags)  
- Host-based rarity + publisher trust  
- **Weighted final risk scoring**

This creates a **CTI fusion detection** that responds dynamically to new MISP data.

---

# 🎯 What This Rule Detects (High Fidelity)

| Detection Category | Supported | Explanation |
|--------------------|----------:|-------------|
| Run / RunOnce persistence | 🟩 Yes | Common post-infection autoruns |
| Winlogon Shell/Userinit hijacks | 🟩 Yes | Core foothold mechanisms |
| AppInit_DLLs (global DLL injection) | 🟩 Yes | Malware DLLs loaded into all GUI processes |
| Services persistence | 🟩 Yes | Modified or malicious Windows services |
| IFEO injection | 🟩 Yes | Redirecting legitimate EXEs to malware |
| COM Hijacking (CLSID/InprocServer32) | 🟩 Yes | Used by APT41, GALLIUM, UNC groups |
| LSA/SSP registration | 🟩 Yes | Credential theft implants |
| User-writable payload paths | 🟩 Yes | Staged loaders under `AppData`, `ProgramData`, `Temp` |
| Implants referencing URLs/IPs/domains | 🟩 Yes | Pull C2 config from registry |
| Rare unsigned persistence binaries | 🟩 Yes | Uses SHA256 prevalence mapping |
| Known malicious IoCs from MISP | 🟩 Yes | Automatic severity uplift |
| Supply-chain persistence after a trojanised update | 🟩 Yes | When update drops persistence keys |

---

# 🔥 **What It Would Catch in Real Supply-Chain Attacks**

## ✔ 3CX Supply Chain (2023)
Payload: **DLL loader-side persistence** using Run keys + sideloaded DLL communication.

| Sub-attack | Detected? | Why |
|------------|----------:|-----|
| DLL loader written to `%AppData%` | 🟩 Yes | User-writable path + SuspFileRef |
| Run key for persistence | 🟩 Yes | Core Run key coverage |
| Config URLs in registry | 🟩 Yes | Network IOC + regex (domain/IP) |
| Sideloaded legitimate signed DLL | 🟥 No | No registry modification in that stage |
| Dormant driver drop | 🟧 Partial | Only if registry is used to store the loader path |

**Detection Strength:** Strong for *post-load* persistence stage.

---

## ✔ SolarWinds SUNBURST (2020)
Payload: Registry-based covert C2 settings + scheduled persistence.

| Sub-attack | Detected? | Why |
|------------|----------:|-----|
| C2 domain encoded in registry | 🟩 Yes | Base64 + domain regex |
| Modified services | 🟩 Yes | `HKLM\SYSTEM\CurrentControlSet\Services` |
| DLL preloading w/o registry changes | 🟥 No | Requires your DLL sideloading rule |
| Native Orion service loads malicious DLL | 🟥 No | Not registry-related |

**Detection Strength:** Strong for *registry-based C2 + persistence*, not for loader stage.

---

## ✔ NotPetya / M.E.Doc (2017)
Payload: Uses **services persistence**, scheduled tasks, wiper routines.

| Sub-attack | Detected? | Why |
|------------|----------:|-----|
| Modified services | 🟩 Yes | Services key monitored |
| Run key for lateral movement tooling | 🟩 Yes | Catches encoded PowerShell |
| Fileless PS commands embedded in registry | 🟩 Yes | Base64 / LOLBin detection |
| SMB lateral movement (PSEXEC) | 🟥 No | Network-level, separate rule |
| Wiper DLL components | 🟥 No | Not registry-persistent |

---

## ✔ NTT Data Attack (your 2025 simulation)
Payload: multi-stage loader → persistence via IFEO + COM hijack.

| Sub-attack | Detected? | Why |
|------------|----------:|-----|
| IFEO debugger hijack | 🟩 Yes | Explicit coverage |
| COM hijack loader | 🟩 Yes | CLSID + InProcServer32 detection |
| Rare unsigned binary dropped | 🟩 Yes | Prevalence scoring |
| Hidden persistence value containing URL | 🟩 Yes | URL + Base64 detection |
| Driver drop (if no registry key used) | 🟥 No | Use Driver Hunt rule |

---

## ✔ F5 Supply-Chain / Appliance Pivot
Payload: attacker pivots from compromised appliance → Windows estate.

| Sub-attack | Detected? | Why |
|------------|----------:|-----|
| Dropper establishes Run key | 🟩 Yes | Registry Run coverage |
| Persistence stored in COM hijack | 🟩 Yes | COM/CLSID logic |
| User-writable loader paths | 🟩 Yes | UserWritableRx |
| Credential-harvesting SSP DLL | 🟩 Yes | LSA keys |
| Appliance-side RCE leading to no registry changes | 🟥 No | Out of scope |

---

# ❌ What This Rule Cannot Detect (By Design)

| Miss | Reason |
|------|--------|
| Pure DLL sideloading | No registry writes |
| Kernel-mode persistence | Needs driver telemetry |
| GPO/SYSVOL registry.pol persistence | Not endpoint-written |
| WMI Event Consumers | Not registry-based |
| Startup folder persistence | File-based, not registry |
| Agentless Linux/Appliance implants | Windows-only scope |

Pair it with your **DLL Sideloading**, **Driver Hunt**, **OAuth Abuse**, **Port Hunt**, **NTDS/Directory Dump** rules.

---

# 🧬 MISP Integration — How It Enhances Detection

The rule joins against:

```
ThreatIntelligenceIndicator
    Indicator (SHA256/file/domain)
    ConfidenceScore
    ThreatType
    Tags
    TLP
```

MISP fields influence:

| MISP Attribute | Impact |
|----------------|--------|
| `ConfidenceScore` | Weighted into final risk scoring |
| `Tags` | Kill-chain relevance (e.g., `delivery`, `installation`) |
| `Indicator` | Hash/domain match instantly boosts severity |
| `TLP` | For sighting/reporting automation |

This makes the rule **self-tuning** as new MISP data lands.

---

# 🎛 Final Risk Score Formula (Readable)

```
FinalScore =
    (DetectionSignal * 0.4)
  + (IntelConfidence * 0.3)
  + (KillChainRelevance * 0.2)
  + (TemporalScore * 0.1)
```

Where:

- **DetectionSignal** = behavioural evidence  
- **IntelConfidence** = MISP confidence (fallback 50)  
- **KillChainRelevance = 80** (weighted for persistence/post-compromise)  
- **TemporalScore = 100** (favours fresh IOCs)  

Risk levels:

| Score | Level |
|-------|--------|
| ≥ 90 | 🔥 CRITICAL |
| ≥ 70 | HIGH |
| < 70 | MEDIUM |

---

# 🕵️ Threat Hunter Directive (Auto-Generated Per Row)

Examples:

- “IMMEDIATE: isolate host, pull memory, block indicators, add MISP sighting.”  
- “URGENT: verify autorun legitimacy, confirm signer, analyze parent process.”  
- “INVESTIGATE: validate value, check recurrence, correlate user/machine.”  
----

