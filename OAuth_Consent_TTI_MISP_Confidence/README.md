# 🔐 OAuth App-Consent Threat Hunt (CTI/MISP Integrated)
**Author:** Ala Dabat  
**Platform:** Microsoft Sentinel  
**Purpose:** Detect malicious OAuth consent grants, high-risk permissions, app-only pivots, token abuse, suspicious user-agents, and CTI-matched malicious AppIDs.  
**MITRE:** TA0001 (Initial Access), TA0003 (Persistence), TA0004 (Privilege Escalation), TA0006 (Credential Access)

---

## 🎯 Objective

This rule detects **malicious OAuth consent abuse** by analysing:

- High-risk OAuth permission grants  
- App-only (“client credentials”) pivots  
- Tenant-wide admin consent  
- Suspicious user-agents (curl/python/Postman/etc.)  
- Non-Microsoft publishers  
- MISP/OpenCTI indicator matches on **AppId**  
- Combined threat scoring (Detection + CTI + Kill Chain + Temporal)

This is the **L3 version** that detects:
- Consent phishing  
- Token hijacking  
- Illicit consent grants  
- Malicious service principal pivots  
- Backdoored apps  
- External attacker footholds using OAuth identity abuse

---

## 🧠 What This Rule Will Catch

| Category | Detected? | Details |
|----------|-----------|---------|
| High-risk delegated permissions | 🟩 Yes | e.g., `Mail.ReadWrite`, `Directory.ReadWrite.All` |
| App-only (client credentials) abuse | 🟩 Yes | Detects machine-to-machine impersonation |
| Tenant-wide admin consent | 🟩 Yes | `"OnBehalfAll == true"` |
| Suspicious user-agent (curl/python/etc.) | 🟩 Yes | Indicates automation or token-harvesting |
| Non-Microsoft publisher | 🟩 Yes | e.g., rogue apps with fake publisher info |
| Mass-permission apps (“super apps”) | 🟩 Yes | 15+ high-risk permissions triggers |
| Backdoored cloud apps | 🟩 Yes | CTI/MISP AppId match boosts score |
| OAuth-based persistence | 🟩 Yes | Attacker uses SP credentials instead of accounts |
| Consent phishing | 🟩 Yes | Social-engineered OAuth grant with high-risk scopes |
| Token replay / token issuance abuse | 🟨 Partial | You already flag suspicious user-agents; adding SignInLogs correlation would make it full |
| Legitimate Microsoft apps | 🟦 Auto-safe | via KnownSafeApps + KnownSafePublishers |

---

## 🧨 Real Attack Coverage

### 🎯 3CX Supply-Chain → OAuth Impersonation
Not part of 3CX directly, but attackers often pivot to cloud identity abuse afterwards:
- They create **malicious Azure apps**  
- Request delegated / app-only permissions  
- Abuse token issuance  

🟩 Your rule **fully detects** this post-exploitation OAuth phase.

---

### 🕵️ SolarWinds (SUNBURST) post-compromise OAuth abuse
SUNBURST operators used:
- Azure apps for persistence  
- Illicit OAuth grants  
- Long-lived refresh tokens  

Your rule would detect:

| Attack Component | Detected? | Explanation |
|------------------|-----------|-------------|
| Malicious AppId | 🟩 Yes | CTI integration |
| Admin consent | 🟩 Yes | `OnBehalfAll` |
| App-only permissions | 🟩 Yes | `IsAppOnly` |
| Suspicious UA | 🟨 Maybe | Depends on UA |
| Token replay | 🟨 Partial | Adding token usage correlation will complete it |

---

### 🕵️ Password Spray → OAuth grant pivot
Attacker gets in → pushes OAuth consent.

Your rule catches:
- Suspicious user-agent → 🟩  
- High-risk scope grants → 🟩  
- Non-Microsoft publisher → 🟩  
- CTI match → 🟩  

This is exactly what this rule is designed for.

---

## 🔬 Scoring Model (L3/Enterprise)

```text
FinalScore =
  (DetectionSignal * 0.40)
+ (CTI_Confidence * 0.30)
+ (KillChainRelevance * 0.20)
+ (TemporalScore * 0.10)
1) Review legitimacy of 'MyCRM Connector' (appId).
2) ConsentType = Admin (tenant-wide)
3) GrantType = Application (client credentials)
4) High-risk permissions: Mail.ReadWrite, Directory.ReadWrite.All
5) TI Score = 85 | Risk = CRITICAL
...
