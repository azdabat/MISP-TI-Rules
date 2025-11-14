# 🧬 L3 Native Hunt — Supply-Chain DLL / Signed Binary Drift (TI-Aware)

**Author:** Ala Dabat  
**Platform:** Microsoft Defender for Endpoint + Sentinel  
**Type:** L3 Hunt / Low-Noise Analytic  
**Scope:** DLL sideloading, signed binary drift, driver + registry + network correlation, TI-aware  
**MITRE:** TA0003, TA0005, TA0011 • T1574.002, T1553.002, T1547.006

---

## 🎯 Detection Goal

Hunt for **supply-chain compromise** and **sideloaded DLLs** in *otherwise legitimate vendor processes* by combining:

- **DLL image loads** into vendor processes (`3cx.exe`, `SolarWinds.BusinessLayerHost.exe`, `bigip_service.exe`, etc.)
- **File creation timing** → immediate vs delayed loads (minutes → 30 days)
- **Integrity drift** → version, signer, hash differences from org baselines
- **Registry persistence references** → DLL paths under Run/Services/COM/LSA
- **Driver activity** → `.sys` drops near the DLL load
- **Network context** → outbound IP/URL/domain from the affected host
- **Threat Intelligence** → hash + IP/Domain/URL IOCs from `ThreatIntelligenceIndicator`

This is a **full-chain supply-chain detector**, not just “DLL loaded by X”.

---

## ✅ What This Rule Will Catch

| Category | Detected? | Details |
|----------|-----------|---------|
| DLL sideloading into vendor processes (3CX, SolarWinds, F5 helpers) | 🟩 Yes | `ImageLoadEvents` + VendorProcesses list |
| Fast loader DLLs (drop → load ≤ 5 min) | 🟩 Yes | `FastLoad` scoring |
| Delayed loaders (5 min → 7 days) | 🟩 Yes | `DormantShort` / `DormantLong` |
| Long-dormant DLLs (up to 30 days) | 🟩 Yes | `DormantVeryLong` — SolarWinds-style |
| Unsigned or untrusted DLLs | 🟩 Yes | `IsUnsigned` and `TrustedSigner` |
| Rare DLLs across the estate | 🟩 Yes | `SeenDeviceCount <= 2` |
| Integrity/Signer/Hash drift of vendor binaries | 🟩 Yes | `VersionDrift`, `SignerDrift`, `HashDrift` |
| Registry persistence referencing DLLs | 🟩 Yes | Run/Services/COM/LSA with `.dll` in data |
| Driver activity near DLL load | 🟩 Yes | `DriverLoads` joined on DeviceId |
| IP/URL/Domain C2 correlated via TI | 🟩 Yes | `TINet` join with `ThreatIntelligenceIndicator` |
| Malicious DLL hash from MISP/OpenCTI (3CX/SUNBURST/F5/etc.) | 🟩 Yes | `TIFile` join on `ImageSHA256` |

---

## 🧨 How It Maps to Real Supply-Chain Attacks

### 3CX Supply-Chain Backdoor

- **DLL dropped under user profile / AppData** → `FileCreates + IsRare`
- **Loaded by `3cx.exe`** → `VendorProcesses + LoaderIsVendor`
- **Delayed execution** → `DormantShort/Long` flags
- **C2 to attacker infra** → `RemoteIP/RemoteUrl` + `TINet` match
- **Hash in MISP** → `TIFile` → **FinalScore → ALERT**

### SolarWinds SUNBURST

- **Malicious Orion DLL** with version/signer/hash drift → `IntegrityDrift`
- **Delayed load weeks later** → `DormantVeryLong`
- **C2 domains/IPs in CTI** → `TINet` boost
- **Hash from TI** → `TIFile` uplift

### F5 BIG-IP / Appliance Pivot

- **F5 helper processes** → `VendorProcesses` (e.g., `bigip_service.exe`)
- **New DLLs/EXEs in same folder / uncommon paths** → `IsRare + HashDrift`
- **Kernel driver drop** → `DriverPath` present → `KillChainScore`
- **C2 to known attacker infra** → `TINet` join

### NotPetya / M.E.Doc

- **Tampered signed binary / DLL** → `SignerDrift`, `HashDrift`
- **Rare across org** → `IsRare`
- **Network beacons to C2** correlated with TI → `TINet`
- **Known hash** → `TIFile` → ALERT

---

## 🧮 Scoring Model

```text
BehaviorScore =
    3*FastLoad
  + 1*DormantShort
  + 2*DormantLong
  + 3*DormantVeryLong
  + 3*IsUnsigned
  + 2*IsRare
  + 2*LoaderIsVendor
  + 3*VersionDrift
  + 3*SignerDrift
  + 3*HashDrift
  - 1*TrustedSigner

KillChainScore = (driver activity) + (registry DLL reference)
RecencyScore   = 10 if load in last 24h

TI_Confidence  = max(File IOC confidence, Network IOC confidence)

FinalScore = (BehaviorScore * 0.4)
           + (TI_Confidence * 0.3)
           + (KillChainScore * 0.2)
           + (RecencyScore * 0.1)
