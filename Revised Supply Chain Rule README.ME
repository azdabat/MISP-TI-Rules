# Supply-Chain Compromise / Signed Binary Drift & DLL-Driver Abuse Detection
**Author:** Ala Dabat  
**Platform:** Microsoft Defender / Sentinel (Advanced Hunting – Native KQL)  
**Classification:** L3 Threat Hunt / Analytic Rule  
**Version:** 2.1 (Enhanced for Integrity Drift)  
**Last Updated:** 2025-11-11  

---

##  Overview
This rule detects **supply-chain compromises** and **signed binary abuse** on endpoints by correlating:
- Signed but **tampered vendor binaries** (version/signature drift)
- **DLL sideloading** and **driver injection** abuse
- **Registry persistence** (ServiceDll, InprocServer32, Run keys)
- **Dormant or delayed activation** typical of SolarWinds/3CX-style implants  
- **Network, process, and driver context** for kill-chain correlation  

It introduces **integrity-drift analytics** to identify binaries whose signature, hash, or version differs from the organization’s baseline, signaling a potential **compromised update or malicious rebuild**.

---

##  Detection Logic Summary

Signed Orion process
↓ loads
Trojanized BusinessLayerHost.dll
↓ dormant 14 days
↓ registry persist (ServiceDll)
↓ driver drop / C2 beacon

 Detected through **DormantVeryLong + SignerDrift + Registry persistence**

---

### 2 3CX Compromise


3cxdesktopapp.exe (signed)
↓ loads
d3dcompiler_47.dll (malicious)
↓ fast-load & network C2

 Detected via **VendorProcess + FastLoad + Unsigned DLL**

---

### 3️ F5 BIG-IP Breach


Vendor service binary (signed)
↓ loads
Injected DLL → drops signed driver
↓ reactivated after reboot

 Detected via **DriverLoad + DormantLong + Registry persistence**

---

##  SOC Hunter Directives
Each alert includes structured guidance in the `HunterDirectives` column:

1. Review loader process & signer integrity  
2. Verify **version / signer / hash drift** vs baseline  
3. Analyze **Create→Load delay** (fast vs dormant)  
4. Check registry persistence near event time  
5. Confirm driver activity or kernel module loads  
6. Investigate related **network connections**  
7. If **ALERT:** isolate host, dump memory, preserve binaries  
8. If **HUNT:** pivot across devices and verify vendor authenticity  

---

##  False-Positive Guidance
| Source | Mitigation |
|---------|-------------|
| Legitimate vendor update | Validate signer + version in vendor release notes |
| Internal software builds | Add internal publisher to `TrustedPublishers` |
| EDR/AV agent self-updates | Verify signer + allowlist path temporarily |

---

##  Deployment Notes
- Designed for **native use** in Microsoft Defender / Sentinel Advanced Hunting.  
- No external TI feeds required.  
- Can be promoted to **Analytic Rule** with alert automation using `Severity=="ALERT"`.  
- For enrichment, integrate with **MISP/OpenCTI** to cross-check drifted binaries with known IoCs.

---

##  Expected Results
| Attack Vector | Detection | Confidence |
|----------------|------------|-------------|
| Vendor binary tampering | ✅ | 🔥 High |
| Dormant or staged loader | ✅ | High |
| BYOVD driver implant | ✅ | High |
| Registry-only persistence | ✅ | Medium-High |
| File-less reflective load | ⚙ Partial | Medium |

---

##  Recommendations
- Add **continuous baseline jobs** for version/signer tracking every 7 days.  
- Integrate **hash drift** with your asset inventory or CMDB for supply-chain integrity monitoring.  
- Maintain an **allowlist file** for legitimate vendor updates (auto-expire after 30 days).  
- Periodically refresh **TrustedPublishers** and **VendorProcesses** lists.

---

##  License & Attribution
© 2025 Ala Dabat – MIT License.  
Free to use, modify, and redistribute with attribution.  
If reused, reference this repo as:  
`https://github.com/azdabat/MISP-TI-Rules`  

---

###  Tags
`#KQL` `#DetectionEngineering` `#SupplyChain` `#DLLHijacking`  
`#DriverAbuse` `#MITREATTACK` `#ThreatHunting` `#IntegrityMonitoring`

| Component | Purpose |
|------------|----------|
| `DeviceFileEvents` | Tracks DLL/EXE/driver creation and version/signature drift |
| `DeviceImageLoadEvents` | Identifies execution or load of suspicious DLLs |
| `DeviceRegistryEvents` | Flags registry-based persistence mechanisms |
| `DeviceEvents` | Detects driver loads (including file-less BYOVD) |
| `DeviceNetworkEvents` | Adds C2 or callback context |
| `OrgPrevalence` | Baselines file rarity across the tenant |
| `IntegrityDrift` | Detects signer/version/hash drift of signed apps |

---

##  Detection Methodology

The rule computes:
- **BehaviorScore** → Execution timing, rarity, unsigned state, vendor loader
- **KillChainScore** → Driver / registry persistence correlation
- **RecencyScore** → Prioritizes new activity  
- **FinalScore = 0.6×Behavior + 0.3×KillChain + 0.1×Recency**

Then classifies as:
| Severity | Threshold | Action |
|-----------|------------|--------|
| **ALERT** | ≥ 75 | Trigger incident, isolate host |
| **HUNT** | 40–74 | Investigate, pivot across estate |
| **LOG** | < 40 | Baseline / telemetry only |

---

##  MITRE ATT&CK Mapping
| Tactic | Technique ID | Description |
|--------|---------------|-------------|
| **Persistence** | `T1547.*` | Registry & service DLL persistence |
| **Defense Evasion** | `T1574.002` | DLL Search Order Hijacking |
| **Privilege Escalation** | `T1547.006` | Driver-based persistence |
| **Execution** | `T1055` | Indirect code load (via DLL/driver) |
| **Command & Control** | `T1071`, `T1105` | Network beaconing / data transfer |
| **Defense Evasion** | `T1553.002` | Code-signing certificate abuse |

---

##  Detection Capabilities by Attack Type

| Attack Type | Example | Coverage |
|--------------|----------|-----------|
| DLL sideloading | SolarWinds, 3CX | ✅ Full |
| Signed driver abuse | F5, BlackByte | ✅ Full |
| Dormant loaders | SUNBURST, CCleaner | ✅ Full |
| Registry persistors | Run / ServiceDll keys | ✅ Full |
| Version/signature drift | Vendor app tampering | ✅ Full |
| File-less in-memory load | Reflective injection | ⚙ Partial |
| Pure cloud/SaaS compromise | Okta / CircleCI | ❌ Out of scope |

---

##  Example Attack Chains Detected

### 1️ SolarWinds / SUNBURST Pattern


---

##  End-to-End Flow Summary

1. **File Drop / Modification:** Suspicious DLL or SYS created on host.  
2. **Execution:** File loaded by signed vendor process (e.g., 3CX.exe).  
3. **Persistence:** Registry or service entry modified to ensure reboot survival.  
4. **Integrity Drift:** Binary’s signer or version deviates from baseline.  
5. **Kill-Chain Correlation:** Network, process, and driver telemetry unified.  
6. **Scoring Engine:** Behavior + Kill-Chain + Recency → FinalScore.  
7. **Analyst Output:** HunterDirectives guide triage, isolation, and validation.

---

###  Visualization Summary
- **Blue boxes (Process/File telemetry)** → `DeviceFileEvents`, `DeviceImageLoadEvents`
- **Orange boxes (Persistence / Drift)** → `DeviceRegistryEvents`, `IntegrityDrift`
- **Green boxes (Execution / Network)** → `DeviceEvents`, `DeviceNetworkEvents`
- **Red box (FinalScore)** → Unified analytic scoring (Alert/Hunt/Log)

---


