# 🔐 SMB Lateral Movement — Enhanced Hunt (NotPetya / PsExec / WMI / SCExec)

**Author:** Ala Dabat  
**Platform:** Microsoft Defender for Endpoint + Sentinel  
**Type:** L3 Threat Hunt / Post-Compromise Lateral Movement Detector  
**MITRE:**  
- **TA0008 – Lateral Movement**  
- **TA0002 – Execution**  
- **TA0006 – Credential Access**  
- **T1021.002 – SMB/ADMIN$ Lateral Movement**  
- **T1569.002 – Service Execution**  
- **T1078 – Valid Accounts**

---

## 🎯 Detection Goal

Detect **SMB-based lateral movement** commonly used in:

- **NotPetya worming**
- **PsExec-style movement**
- **WMI / WMIC lateral execution**
- **SC.exe service drop + remote execution**
- **Post-compromise ADMIN$ share writes**
- **Propagation across multiple hosts**
- **Credentialed lateral movement using NTLM / Kerberos**
- **TI-flagged remote hosts (C2 or worm infrastructure)**

This rule correlates **4 independent signals**:

1. SMB connection to port 445 from high-risk tools  
2. ADMIN$ share file writes  
3. Remote service creation/execution (PsExec, SCExec, svchost misuse)  
4. TI + DNS + authentication context  

…within a **15-minute correlation window**.

---

# ✔ What This Rule **Will Detect**

| Detection Category | Detected? | Why |
|-------------------|-----------|------|
| PsExec lateral movement | 🟩 Yes | Detects psexec.exe, psexesvc + ADMIN$, + remote service |
| WMI / WMIC remote execution | 🟩 Yes | wmic.exe + SMB admin share + svc creation |
| SC.exe remote service deployment | 🟩 Yes | “sc.exe create/start” correlations |
| NotPetya worm movement | 🟩 Yes | ADMIN$ write → service drop → execution chain |
| Multi-host propagation | 🟩 Yes | `HostPropagationCount` scoring |
| NTLM/Kerberos authenticated SMB lateral movement | 🟩 Yes | SigninLogs enrichment |
| C2-assisted SMB movement | 🟩 Yes | ThreatIntelligenceIndicator join |
| DNS mapping of RemoteIP → hostname | 🟩 Yes | DnsEvents mapping |

---

# ❌ What This Rule **Will NOT Detect**

| Missed Scenario | Reason |
|-----------------|--------|
| Pure RDP lateral movement | RDP/3389 not included |
| Remote WMI without SMB (DCOM only) | No port 445 usage → out of scope |
| Lateral movement via WinRM/5985 | No SMB component present |
| Pass-the-Hash without ADMIN$ writes | Needs file-write + service execution for detection |
| Credential stuffing brute-force | Not an authentication detector |
| Memory-only remote injection (no service/PsExec) | Requires file/service artefacts |
| Zerologon / Kerberos privilege escalation | Authentication anomaly, not SMB-based |

---

# 🧨 Real-World Attack Coverage

## **NotPetya (M.E.Doc → Worm Stage)**  
| Technique | Covered? | Explanation |
|----------|----------|-------------|
| Credential theft then SMB spread | 🟩 | Multiple 445 connections from same host |
| ADMIN$ payload deployment | 🟩 | File writes to ADMIN$ share |
| Service creation on remote host | 🟩 | PsExec-style svc drop detection |
| Worm propagation | 🟩🟩 | `HostPropagationCount >= 3` triggers **WORM MODE** |

---

## **Conti / Ryuk PsExec Lateral Movement**
| Technique | Coverage |
|----------|----------|
| PsExec.exe → remote service → payload drop | 🟩 Full |
| Multiple hosts fanned out from one device | 🟩 High |
| Use of compromised domain admins | 🟩 Medium (SigninLogs context) |

---

## **SC.exe Backdoor Deployment**
| Technique | Coverage |
|----------|----------|
| sc.exe create + start remote svc | 🟩 Strong |
| ADMIN$ write of malicious EXE | 🟩 Strong |

---

## **WMI / WMIC Lateral Execution**
| Technique | Coverage |
|----------|----------|
| wmic.exe process calling remote host | 🟩 Yes |
| Followed by SMB + svc creation | 🟩 Yes |
| Pure WMI (no SMB) | ❌ Not detected |

---

# 🧮 Scoring Model (Simple)

```text
DetectionSignal = 90
KillChainRelevance = 85
TemporalScore = 100
FinalScore = 
    0.4 * DetectionSignal
  + 0.2 * IntelConfidence
  + 0.2 * KillChainRelevance
  + 0.1 * TemporalScore
  + 3   * HostPropagationCount
Worm propagation bonus:
If ≥3 hosts are touched → massive score spike.

🕵️‍♂️ Embedded Hunter Directives

Your rule automatically assigns analyst workflow guidance:

Propagation ≥3 hosts:
“IMMEDIATE: Likely worm; isolate source, block SMB, dump memory.”

CRITICAL score:
“Isolate source, confirm payload in ADMIN$, disable PsExec, notify IR.”

HIGH:
“Review service creation and validate credentials.”

Medium:
“Investigate abnormal ADMIN$ access.”

📦 Included Data Enrichment

DNS → resolved hostname of remote target

NTLM/Kerberos logons → session clarity

TI IOCs → C2 or known worm infra

SHA256 of dropped ADMIN$ binaries

Service name, command line, invoking parent process

Host-to-host spread patterns

🧪 Example Evidence Object
{
  "SMBProc": "psexec.exe",
  "SMBCmd": "psexec \\\\10.10.5.30 cmd",
  "TargetHost": "DESKTOP-45F1",
  "AdminShareFile": "psexesvc.exe",
  "SvcFile": "ServiceCreation",
  "SvcCmd": "sc.exe create blahblah",
  "PropagationCount": 4
}

🏁 Summary

This is a high-fidelity, low-noise L3 threat hunting rule optimised for:

Worm propagation

PsExec / WMI lateral movement

Multi-signal correlation

Real DFIR-style investigation paths

Fast detection of destructive spread like NotPetya
