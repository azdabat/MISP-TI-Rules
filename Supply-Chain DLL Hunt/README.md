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

## ⚙️ Behaviour & Scoring Logic

### **BehaviorScore (40%)**

