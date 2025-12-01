# MISP-Integrated Threat Hunting & Supply-Chain Detection Rules  
**Author:** Ala Dabat — Senior SOC / Threat Intelligence / Detection Engineering  
**Platform:** Microsoft Sentinel & Microsoft Defender for Endpoint  
**Focus:** Supply-chain intrusion detection, adaptive confidence scoring, registry and driver persistence, OAuth abuse, SMB lateral movement, rogue endpoint discovery, and TI-enriched C2 correlation.

---

## Overview  
This repository contains a suite of **production-ready behavioural and TI-integrated KQL detection rules** designed to identify high-impact modern attack techniques, particularly those seen in **supply-chain compromises** and **identity-centric intrusions**.

The rule logic focuses on:

- Registry-based persistence (Run keys, LSA, COM hijacking, IFEO)
- Supply-chain DLL drift (version/hash/signer changes)
- Driver tampering & BYOVD implants  
- OAuth consent abuse  
- Rogue endpoint discovery (hostname anomalies, unmanaged devices)
- SMB / PsExec / WMI lateral movement  
- LSASS memory access  
- C2 communication (TI-matched ports, IPs, JA3, domains)

Each rule follows a consistent structure:

1. **Behavioural signal**  
2. **Registry / process / driver correlation**  
3. **Network or identity context**  
4. **MISP/OpenCTI enrichment (where available)**  
5. **Adaptive scoring** → Low / Medium / High / Critical  
6. **Hunter Directives** (for L1/L2 triage flow)

The rules are optimised for **low noise**, **explainability**, and **alignment with MITRE ATT&CK**.

---

# 1. Detection Logic Overview

## 1.1 Registry Persistence — MISP-Enriched  
Detects:
- Run keys and Services tampering  
- ServiceDLL hijack  
- COM hijack  
- IFEO debugger abuse  
- LSA extension tampering  
- Encoded or obfuscated payloads  
- DLL persistence under user-writable paths  
- TI-matched hashes/domains/IPs

MITRE: T1112, T1547, T1543  
Tables: `DeviceRegistryEvents`, `DeviceImageLoadEvents`, `DeviceProcessEvents`

---

## 1.2 DLL / Driver Drift — Supply-Chain Core  
Detects:
- Signed binary drift (version/hash/signer mismatch)  
- Delayed activation patterns (e.g., SUNBURST/3CX)  
- Malicious DLL alongside legitimate process lineage  
- Driver drops (BYOVD)  
- Registry persistence + lateral context  
- TI-enriched C2 indicators

MITRE: T1574.002, T1587, T1556.004  
Tables: `DeviceImageLoadEvents`, `DeviceFileEvents`, `DeviceProcessEvents`, `DeviceRegistryEvents`

---

## 1.3 Advanced SMB Lateral Movement — NotPetya-Style  
Detects:
- ADMIN$ share propagation  
- PsExec / Service Creation (EventID 7045)  
- WMI remote execution  
- Credential reuse patterns  
- SMB worm-like fan-out  
- TI-matched internal/external IPs

MITRE: T1021.002, T1570  
Tables: `DeviceNetworkEvents`, `DeviceProcessEvents`, `SecurityEvent`

---

## 1.4 OAuth App-Consent Abuse  
Detects:
- Unknown publishers  
- High-risk delegated scopes  
- Suspicious user agents  
- OAuth credential additions  
- Token misuse patterns

MITRE: T1528, T1098  
Tables: `AuditLogs`, `SigninLogs`, `CloudAppEvents`

---

## 1.5 Rogue Endpoint + LDAP + LSASS Hunt  
Detects:
- Unmanaged or anomalous device names  
- Host-naming conventions not matching baseline  
- LDAP enumeration (389/636)  
- LSASS handle access attempts  
- Credential harvesting behaviour

MITRE: T1003.001, T1087  
Tables: `DeviceProcessEvents`, `DeviceNetworkEvents`, `SecurityEvent`, `DeviceInfo`

---

## 1.6 Suspicious Ports + TI Correlation  
Detects:
- Known C2 ports  
- DoH exfiltration  
- RCE staging ports  
- TI-matched external IPs/domains

MITRE: T1041, T1568  
Tables: `DeviceNetworkEvents`, external CSV TI

---

# 2. Supply-Chain Attack Diagrams (ASCII)



## 2.1 SolarWinds (SUNBURST)

~~~
[1] Build System Compromise → DLL injection into Orion platform
[2] Signed Update Delivery → Malicious DLL signed by SolarWinds cert
[3] Delayed Activation → Environment checks, dormant execution
[4] DNS-based C2 → avsvmcloud[.]com, rotating subdomains
[5] Second-stage Loaders → TEARDROP / RAINDROP
[6] Lateral Movement → PsExec, WMI, Golden SAML
[7] Persistence → Run keys, ServiceDLL
~~~

## 2.2 NotPetya (M.E.Doc)

~~~

[1] Compromised build pipeline
[2] Signed DLL replaced → loader
[3] Dormant period → delayed C2
[4] Stage-2 payload via encrypted channel

~~~

## 2.4 F5 / UNC5221

~~~
[1] Malicious driver (signed) dropped
[2] ServiceDLL hijack persists driver
[3] Lateral movement via ADMIN$
[4] OAuth malicious app pivot
[5] Exfiltration → cloud infra
~~~

---

# 3. Coverage Matrix

| Attack       | DLL Drift | Registry | SMB | OAuth | C2/Ports | BYOVD | Coverage |
|--------------|-----------|----------|-----|-------|----------|-------|----------|
| SolarWinds   | ✔         | ▲        | ✔   | ▲     | ✔        | ✗     | ~75%     |
| 3CX          | ✔         | ▲        | ✔   | ✗     | ✔        | ✗     | ~90%     |
| NotPetya     | ▲         | ✔        | ✔   | ✗     | ▲        | ✗     | ~85%     |
| F5/UNC5221   | ▲         | ✔        | ✔   | ✔     | ✔        | ✔     | ~80%     |
| Vectorform   | ▲         | ▲        | ✔   | ✗     | ▲        | ✗     | ~90%     |

Legend: **✔ strong**, **▲ partial**, **✗ none**

---

# 4. Rule Suite Summary

### Supply-Chain DLL Hunt  
- Detects signer/hash/version drift  
- Flags DLL/driver mismatch  
- Identifies dormant loaders  
- TI match (MISP/OpenCTI)

### Registry Persistence Hunt  
- Detects Run keys, ServiceDll, IFEO, LSA tampering  
- TI enrichment for hashes/domains  
- Includes severity scoring

### SMB Lateral Movement  
- ADMIN$, PsExec, WMI, MS17-010 indicators  
- Fan-out pattern scoring  
- Service creation signal

### OAuth Consent Abuse  
- High-risk scopes  
- Unknown publishers  
- Suspicious user-agents

### Rogue Endpoint + LSASS  
- Hostname anomalies  
- Unmanaged devices  
- LDAP/LSASS correlation

---

# 5. Future Additions  
- Golden SAML detection  
- DGA outbound behaviour  
- Cloud API exfiltration analytics  
- BYOVD behavioural model  
- LSASS memory access (ETW)  
- Zero-day behavioural modelling (honeypot TI)

---

# 6. Key Principles  
- Behaviour first, TI second  
- Baseline drift = universal supply-chain signal  
- TI confidence scoring improves priorities  
- Chain-of-evidence detection (registry + process + driver + network)  
- Rules written for **SOC operators, detection engineers, and IR teams**

---

# 7. Directory Shortcuts  
- Supply-Chain DLL Hunt  
- BYOVD Detection  
- OAuth Consent Abuse  
- Registry Persistence  
- SMB Lateral Movement  
- TOR Exit Node Detection  
- Suspicious Ports (CSV)

---

# Closing Note  
These rules represent the direction modern SOC detection engineering is moving toward:  
**behavioural analytics strengthened through contextual intelligence**.


