## 🛰️ TOR Exit Node Communication — MISP-Enriched Threat Hunt  
**Author:** Ala Dabat  
**Platform:** Microsoft Sentinel  
**Category:** Threat Hunting | Egress Monitoring | CTI-Driven  
**MITRE:**  
- **TA0011: Command & Control**  
- **TA0010: Exfiltration**  
- **T1090: Proxy**  
- **T1573: Encrypted Channel**  
- **T1071: Application Layer Protocol**

---

# 🧠 What This Hunt Detects
This hunt identifies **any endpoint communicating with TOR exit nodes**, enriched with **MISP/OpenCTI threat intelligence**, and provides **full process, command-line, and account context** for triage.

### ✔ Detects:
| Behaviour | Detected? | Notes |
|----------|-----------|-------|
| Outbound to TOR Exit Nodes | 🟩 Yes | Using external TOR list  
| Inbound from TOR Exit Nodes | 🟩 Yes | Very rare → high-fidelity  
| Suspicious processes using TOR | 🟩 Yes | From MDE network telemetry  
| Suspicious command-lines | 🟩 Yes | curl, powershell, python, etc.  
| MISP-enriched malicious IPs | 🟩 Yes | TI scoring added  
| Repeat TOR connections | 🟩 Yes | Count + first/last seen  
| User account involved | 🟩 Yes | For credential misuse pivot  
| MITRE categories | 🟩 Yes | Automatically included  

### ❌ Does NOT detect:
| Category | Why Not |
|----------|---------|
| TOR hidden service access (onion sites) | Not visible in MDE network logs  
| VPN → TOR chaining | Appears as VPN exit node, not TOR  
| TOR-like custom proxies | Requires separate behavioural model  
| TOR pluggable transports | Obfuscation hides TOR signature  

---

# 🔍 Detection Logic (KQL)  
Lightweight, no paired joins except MISP lookups.

```kql
// ----------------------------------------------------
// TOR Exit Node + MISP Intelligence (Lightweight Hunt)
// Author: Ala Dabat
// ----------------------------------------------------

// TOR exit list
let TorExitNodes =
    externaldata(dest_ip:string)
    ["https://raw.githubusercontent.com/mthcht/awesome-lists/main/Lists/TOR/only_tor_exit_nodes_IP_list.csv"]
    with (format="csv", ignoreFirstRecord=true);

// CTI / MISP
let MISP =
    ThreatIntelligenceIndicator
    | where IndicatorType in ("IP","URL","DomainName")
    | project TI_Indicator=Indicator,
              TI_Confidence=ConfidenceScore,
              ThreatType,
              TLP=TlpLevel,
              Tags;

// TOR → set for fast lookup
let TorIPs = TorExitNodes | distinct dest_ip;

// Main Hunt
DeviceNetworkEvents
| where RemoteIP in (TorIPs)
| join kind=leftouter (MISP)
    on $left.RemoteIP == $right.TI_Indicator
| extend Direction = iif(ConnectionDirection == "Outbound", "Outbound to Tor", "Inbound from Tor")
| extend VT_Link = strcat("https://www.virustotal.com/gui/ip-address/", RemoteIP)
| summarize
    FirstSeen=min(Timestamp),
    LastSeen=max(Timestamp),
    Count=count(),
    Processes=make_set(InitiatingProcessFileName),
    Cmds=make_set(InitiatingProcessCommandLine),
    Accounts=make_set(InitiatingProcessAccountName),
    Ports=make_set(RemotePort),
    TI_Hit = any(TI_Indicator),
    TI_Confidence = max(TI_Confidence),
    TI_Type = any(ThreatType)
  by DeviceName, RemoteIP, Direction
| extend RiskLevel = case(
    TI_Hit == true and TI_Confidence >= 80, "CRITICAL",
    TI_Hit == true, "HIGH",
    Direction == "Outbound to Tor", "MEDIUM",
    "LOW"
)
| extend MITRE_Tactics = "TA0011 C2; TA0010 Exfiltration; TA0007 Discovery",
         MITRE_Techniques = "T1090 Proxy; T1071 Application Layer Protocol; T1573 Encrypted Channel"
// Hunter Directives
| extend HuntingDirectives = pack_array(
    strcat("1. TOR communication detected (", Direction, ")."),
    strcat("2. Processes: ", array_join(Processes, ", ")),
    strcat("3. CommandLines: ", array_join(Cmds, " | ")),
    strcat("4. Accounts involved: ", array_join(Accounts, ", ")),
    strcat("5. Ports used: ", array_join(Ports, ", ")),
    strcat("6. TI Hit: ", iif(TI_Hit,"Yes","No"), " | ThreatType=",coalesce(TI_Type,"None")),
    strcat("7. TI Confidence: ", tostring(TI_Confidence)),
    strcat("8. VT Reputation: ", VT_Link),
    "9. Next steps: Check for data exfil, lateral movement, 3CX/F5 indicators, and anomalous OAuth tokens."
)
| order by RiskLevel desc, Count desc, FirstSeen asc
```

---

# 🧵 Supply Chain Relevance
TOR exit nodes were used in:

| Attack | Role of TOR | Would This Rule Catch It? |
|--------|--------------|---------------------------|
| **3CX Supply-Chain (2023)** | C2 proxying + staging | 🟩 Yes (TOR C2) |
| **F5 Big-IP Exploits** | Exfil & discovery via TOR | 🟩 Yes |
| **SolarWinds SUNBURST** | Proxy layer used by subgroups | 🟨 Partially (only TOR C2, not DNS C2) |
| **NotPetya M.E.Doc** | Not TOR-based | ❌ No |
| **Modern APT phishing → OAuth token theft** | TOR for token replay | 🟩 Yes |

----
Just tell me:  
**“Organise my GitHub repo.”**
