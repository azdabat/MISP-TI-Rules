# 🧬 L3 Native Hunt — Supply-Chain DLL / Signed Binary Drift (TI-Aware)

**Author:** Ala Dabat  
**Platform:** Microsoft Defender for Endpoint & Microsoft Sentinel  
**Type:** L3 Hunt / Low-Noise Analytic  
**Scope:** DLL sideloading, signed binary drift, driver/registry/network correlation, TI-aware  
**MITRE:** TA0003 • TA0005 • TA0011  
**Techniques:** T1574.002 • T1553.002 • T1547.006  

---

## 🎯 Detection Goal

This analytic identifies **supply-chain compromise** patterns by correlating:

- DLL image loads into trusted vendor processes  
- Immediate vs delayed vs long-dormant loader behaviour  
- Signed binary drift: version, signer, hash mismatch  
- Registry persistence referencing DLL paths  
- Driver drops (.sys) in same timeframe  
- Network activity to suspicious IP/Domain/URL  
- Hash and network indicators from CTI/MISP/OpenCTI  

This is a **full-chain supply-chain detector**, not a simple DLL load check.

---

## ✅ What This Rule Detects

| Category | Detected? | Explanation |
|----------|-----------|-------------|
| DLL sideloading into vendor processes | ✔ Yes | Targets 3CX, SolarWinds Orion, F5 BIG-IP helpers, etc. |
| Fast DLL loads (≤5 min) | ✔ Yes | Detects immediate drop → execute behaviour. |
| Delayed DLL loads (5 min → 7 days) | ✔ Yes | Supply-chain stage-2 activation. |
| Long-dormant loaders (7 → 30 days) | ✔ Yes | SolarWinds-style delayed activation. |
| Rare DLLs across org | ✔ Yes | Seen on ≤2 devices. |
| Integrity drift (version/signer/hash) | ✔ Yes | Core supply-chain tampering indicator. |
| Registry persistence referencing DLLs | ✔ Yes | Run/COM/Services/LSA persistence. |
| Driver drops near DLL load | ✔ Yes | Detects kernel-level persistence. |
| Network C2 via IP/URL/Domain | ✔ Yes | NetCtx + TI correlation. |
| MISP CTI hash matches | ✔ Yes | High confidence via TIFile join. |
| Network IOC matches | ✔ Yes | Domain/IP/URL (TINet). |

---

## 🧨 Real-World Attack Coverage

### **3CX Supply-Chain Backdoor**
✔ DLL sideloading into `3cx.exe`  
✔ Immediate or delayed load  
✔ MISP hash match  
✔ C2 to attacker infra  
✔ Rare DLL across endpoints  
✔ Integrity drift

### **SolarWinds SUNBURST**
✔ Very long dormant loaders  
✔ Version/signer/hash drift  
✔ C2 domain correlation  
✔ DLL inside trusted vendor binary  

### **F5 BIG-IP Backdoor**
✔ Vendor-specific loader process  
✔ Rare DLL in unusual folder  
✔ Driver drops (.sys) for persistence  
✔ C2 match via TI  

### **NotPetya / M.E.Doc**
✔ Signed binary tampering  
✔ DLL swapped in trusted folder  
✔ Network beaconing  
✔ Integrity drift detection  

---

# 🔍 Supply-Chain Attack Detection Matrix  
### Using: L3 DLL / Signed Binary Drift + Driver + Registry + TI Correlation Rule

| Attack / Technique Area | DLL Load Detection | Fast Load | Dormant Loader | Version / Signer Drift | Rare DLL | Registry Persistence | Driver Activity | C2 / Network TI | Hash TI Match | Overall Coverage |
|-------------------------|-------------------|-----------|----------------|-------------------------|----------|----------------------|-----------------|------------------|----------------|------------------|
| **3CX Supply-Chain (2023)** | 🟩 | 🟩 | 🟨 (short delay) | 🟨 | 🟩 | 🟨 | ❌ | 🟩 | 🟩 | **High** |
| **SolarWinds SUNBURST (2020)** | 🟩 | ❌ (no fast load) | 🟩🟩🟩 (weeks-long dormancy) | 🟩🟩 | 🟩 | 🟨 | ❌ | 🟩 | 🟩 | **Very High** |
| **F5 BIG-IP Backdoor/Persistence (2024/25)** | 🟩 | 🟨 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | **Very High** |
| **M.E.Doc / NotPetya (2017)** | 🟩 | 🟨 | 🟨 | 🟩 | 🟩 | 🟩 | ❌ | 🟩 | 🟨 | **High** |
| **CCleaner Backdoor (2017)** | 🟩 | 🟩 | 🟨 | 🟩 | 🟩 | ❌ | ❌ | 🟩 | 🟩 | **High** |
| **Kaseya VSA / REvil (2021)** | 🟩 | 🟩 | 🟨 | 🟨 | 🟨 | 🟩 | ❌ | 🟩 | 🟨 | **Medium-High** |
| **XZ Backdoor (2024)** | 🟨 | ❌ | ❌ | 🟩 | 🟨 | ❌ | ❌ | 🟨 | 🟩 (if Windows port) | **Medium** |
| **Ivanti / VPN Appliance Chains (2024/25)** | 🟨 (if DLL dropped) | ❌ | ❌ | 🟨 | ❌ | ❌ | ❌ | 🟩 | 🟩 | **Low-Medium** |
| **3CX Stage-2 (Icon/SVG steganography)** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | 🟨 | ❌ | **Minimal** |
| **Memory-Only Implants (various)** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | **None** |

🟩 Strong Detection 🟨 Partial Detection ❌ Not Detected  

## ⚙️ Behaviour & Scoring Logic

### **BehaviorScore (40%)**

3 × FastLoad
1 × DormantShort
2 × DormantLong
3 × DormantVeryLong
3 × IsUnsigned
2 × IsRare
2 × LoaderIsVendor
3 × VersionDrift
3 × SignerDrift
3 × HashDrift
−1 × TrustedSigner


### **KillChainScore (20%)**
- +1 if driver loaded  
- +1 if registry DLL reference  

### **RecencyScore (10%)**
- +10 if DLL load occurred in last 24h  

### **TI_Confidence (30%)**
- Max(file IOC, network IOC) confidence

### **Final Formula**


---

## 🧭 Hunter Directives (Embedded in Output)

Each output row includes these steps (auto-generated):

1. Identify loader process + signer  
2. Confirm version/signer/hash drift  
3. Inspect Create→Load timing (fast vs dormant)  
4. Review registry persistence references  
5. Check driver activity around same timestamp  
6. Inspect C2 traffic (RemoteIP/Domain/URL)  
7. Review TI match and threat type  
8. **If ALERT:** isolate host & collect binary samples  
9. **If HUNT:** pivot on version/signer drift across org  

---


---

## 📝 Notes

- Designed as an **L3 hunt rule**, not a high-volume analytics rule  
- Excellent for audits, IR investigations, supply-chain compromise checks  
- Works best when combined with TI feeds (MISP/OpenCTI)  
- Detects: fast loaders, delayed loaders, long-dormant loaders, registry + driver persistence, integrity drift, C2 beacons  

This is a **high-fidelity**, **low-false-positive**, **full-chain** supply-chain compromise detector.

---




