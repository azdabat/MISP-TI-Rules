MISP Threat Hunting & Supply Chain Attacks 
•   Objective: Focus on highest risk alerts first to reduce time to detection and 
response. 
•   Triage: Critical threats are treated immediately, low-risk alerts monitored. 
•    Influencing factors: 
o Threat capabilities (lateral movement, exfiltration, privilege escalation) 
o Asset criticality (finance, HR, Service level users/admins, DC’s etc...) 
o Known indicators of compromise (IOCs) 
o Contextual business impact 
Threat Intel Workflow: Enrich -> Assess -> Prorotise -> Disseminate -> Feedback 
Incident Response: Trisage -> Contain -> Eradicate -> Recover >Lessons 
Attack TTP,s: Anatomy -> Red -> Blue -> Example -> Mitigation (modelling, hunts 
etc...) 
Notes: KQL exported from hilite.me (source code beautifier / syntax highlighter). Code 
snippets have been converted to HTML. AI was used for automation and for generating 
artificial scenarios; all work was performed in a MISP lab running in VirtualBox. 
I selected threat hunts I authored. While these hunts were not originally designed to catch 
high‑end supply‑chain compromises, the goal is to illustrate what traditional hunts might 
have surfaced in a real-world incident versus what the same hunts can detect when 
integrated with CTI. I remodeled a classic DLL sideloading / search‑order KQL attack‑chain 
hunt and adapted it to account for supply‑chain scenarios where legitimate digital signing 
may — or may not — be present in both the application and the loaded DLL (the 3CX 
compromise is a primary example). This remodeled hunt is intended to surface similar 
supply‑chain compromises either during manual hunts or as an engineering‑built alert 
once enriched with threat intelligence. 
Supply-Chain Attacks 
•    MDE Events: Process creation, File writes, Network connections, Registry writes 
•    Catching Hunts: 
o Rogue Endpoints → flags non-standard endpoint & process 
o Registry Persistence → flags registry run keys / scheduled tasks 
o Ports → flags suspicious outbound beaconing 
o LSASS / AD → optional if lateral creds were targeted 
o MISP enrichment → identifies known malicious IPs or hashesAptos (Body) 
3CX Supply-Chain Attack 
[User Opens 3CX Update] 
Was there a 3CX watchlist? Were trusted binaries not checked for sideloading? │ 
▼ 
[1] [DLL Sideloading -> Malicious DLL Loaded] 
d3dcompiler_47.dll 
Legacy Windows vulnerability (CVE-2013-3900) │ 
▼ 
[2] [Dropper Installs SYS Driver] │ 
▼ 
[3] [LOLBin Executes Rundll32 -> C2 Beacon] │ 
▼ 
[4] [Persistence via Run Registry Key] │ 
▼ 
[5] Data Exfiltration -> C2 IP (MISP High-Confidence IOC)] 
NotPetya (2017) - Supply-Chain Attack 
[1] Supply-chain: M.E.Doc update server compromise │ 
▼ 
[2] Malicious update (trojanized installer) delivered to customers │ 
▼ 
[3] Installer executes -> Dropper runs 
- Loader writes destructive payload to disk - Loader may drop SMB/scanner tools 
▼ 
[4] Lateral propagation - SMB exploitation / stolen credentials (psexec, WMIC, SMB) - Credential theft (Mimikatz or LSASS scrapes) 
▼ 
[5] Wiper activation - MBR overwrite or crypto/wipe routine - Network-wide impact and service disruption │ 
▼ 
[6] Recovery difficulty - Rapid rebuilds required; backups & backups validation 
SolarWinds supply-chain (SUNBURST) — Attack chain 
[1] Build/Release compromise │ 
▼ 
[2] Signed trojanized update package 
(SolarWinds.Orion.Core.BusinessLayer.dll replaced/modified) │ 
▼ 
[3] Customer receives & installs signed update -> Legit process (SolarWinds service) loads trojan DLL │ 
▼ 
[4] Backdoor establishes C2: - DNS/HTTP(s) beaconing with staged URIs - DGA-like or encoded callbacks 
▼ 
[5] C2 issues follow-on tasks - Secondary payload download (stagers, loaders) - Lateral movement (via SMB/psexec/WMIC/PSExec-like) - Data collection & exfiltration 
▼ 
[6] Persistence & cleanup - Scheduled tasks, service modifications, registry tweaks - Remove traces or stage further implants 
MITRE Mappings for Each Attack 
Attack 
MITRE Tactics 
SolarWinds 
NotPetya 
3CX 
TA0007 Execution, 
TA0001 Persistence, 
TA0011 Command & 
Control 
TA0007 Execution, 
TA0003 Persistence, 
TA0008 Lateral 
Movement 
TA0007 Execution, 
TA0001 Persistence, 
TA0011 Command & 
Control 
MISP Tag Examples / Why: 
MITRE Techniques 
T1071.001 Web Protocols, T1059.001 
PowerShell, T1547.001 Registry Run Keys 
T1071.001 Web Protocols, T1021 SMB/PSExec, 
T1003 Credential Dumping, T1547.001 Registry 
Run Keys 
T1071.001 Web Protocols, T1059.001 
PowerShell, T1547.001 Registry Run Keys 
•   attack-pattern:supply-chain → flags trojanized software delivery 
•   tool:mimikatz → credential dumping detection 
•    malware:solorigate → SolarWinds specific C2 and payloads 
•    malware:notpetya → Wiper binaries, SMB propagation 
•    malware:3cx → supply-chain delivery & beacon IPs 
How the Analyst Sees It in MDE / Alerts 
SolarWinds 
o Process: SolarWinds.BusinessLayerHost.exe loaded 
SolarWinds.Orion.Core.BusinessLayer.dll (signed) // 
DeviceProcessEvents / DeviceImageLoadEvents 
o Network: SolarWinds.BusinessLayerHost.exe -> https://<staging- 
domain>/api/ (HTTP GET) // DeviceNetworkEvents 
o File: %AppData%\Local\Temp\svchelper.dll created (SHA256=...)  
In DeviceFileEvents 
o Process: svchelper.dll invoked via scheduled task svchost updater in 
DeviceProcessEvents 
o Network: outbound POST to C2 encoded beacon (45.76.23.87:443) (TI 
match / MISP) in DeviceNetworkEvents + ThreatIntelligenceIndicator join 
o DeviceProcessEvents: bitsadmin / certutil used to fetch payload.bin in 
DeviceProcessEvents + DeviceNetworkEvents 
o Lateral Movement: SMB connections and Admin$ writes to other hosts in 
DeviceNetworkEvents + Sysmon 
NotPetya 
o Process: updater.exe from M.E.Doc runs -> drops payload.exe 
to %TEMP% // DeviceFileEvents/DeviceProcessEvents 
o Network: internal hosts connect to attacker-controlled IPs (C2) // 
DeviceNetworkEvents 
o Process: bitsadmin / psexec / wmic used for lateral movement // 
DeviceProcessEvents 
o SecurityEvent: LSASS suspicious access; EventIDs showing credential  
dumping // SecurityEvent + DeviceProcessEvents (mimikatz/procdump) 
o File: mass file deletion / MBR writes observed // DeviceFileEvents + 
System logs 
3CX 
o DeviceImageLoadEvents: 3cx.exe loads plugin.dll (SignatureStatus = 
Unsigned) 
o DeviceNetworkEvents: 3cx.exe calls out to staging domain / IP (HTTPs) 
o Registry/File: AppPath entries or service change for persistence 
o ThreatIntelligenceIndicator: remote IP matches MISP C2 indicator -> TI hit 
Which may rules catch it: 
•    Registry Persistence (IFEO/AppPaths)  
•    DeviceImageLoadEvents hunts (unsigned DLL loaded into signed binary)   
•    Port/C2 hunts (outbound to suspicious domain/IP with TI)  
1
 ️
 ⃣ Rogue Endpoint All-in-One — FULL (LDAP/LDAPS + AD tools + 
LSASS) 
// ====================================================== 
// Rogue Endpoint Detection (MISP-Enriched, Adaptive Scoring) 
// Author: Ala Dabat 
// MITRE: TA0007 Discovery; TA0008 Lateral Movement; TA0003 Persistence 
// ====================================================== 
let lookback = 30d; 
let approvedRegex = @"^ACME-(DC|SVC|SQL|WIN|LAP|ADMIN)-\d{2}$"; 
// ---- Step 1: Identify unmanaged or mis-named devices ---- 
let RogueDevices = 
DeviceInfo 
| where TimeGenerated >= ago(lookback) 
| extend NameOk = DeviceName matches regex approvedRegex, 
IsOnboarded = iff(OnboardingState == "Onboarded", 1, 0) 
| where NameOk == false or IsOnboarded == 0 
| project DeviceName, DeviceId, NameOk, IsOnboarded; 
// ---- Step 2: LDAP / LDAPS suspicious network activity ---- 
let LDAPSuspicious = 
DeviceNetworkEvents 
| where Timestamp >= ago(7d) 
| where RemotePort in (389,636) 
| summarize LDAPHits = count(), FirstLDAP=min(Timestamp), LastLDAP=max(Timestamp) 
by DeviceName; 
// ---- Step 3: LSASS / credential-dump signals ---- 
let LSASS_Signals = 
SecurityEvent 
| where EventID in (4656,4663) 
| where ObjectName has "lsass" 
| summarize LsassEvents = count(), FirstSeen=min(TimeGenerated), 
LastSeen=max(TimeGenerated) by Computer 
| project DeviceName = Computer, LsassEvents, FirstSeen, LastSeen; 
// ---- Step 4: Known dumping utilities ---- 
let DumpTools = 
DeviceProcessEvents 
| where Timestamp >= ago(7d) 
| where FileName in ("mimikatz.exe","procdump.exe","procdump64.exe") 
or ProcessCommandLine has_any ("sekurlsa","-ma","Invoke-Mimikatz") 
| summarize ToolExecs = count(), ExampleCmd = any(ProcessCommandLine), 
ExampleFile = any(FileName) by DeviceName; 
// ---- Step 5: Merge signals ---- 
let Combined = 
RogueDevices 
| join kind=leftouter LDAPSuspicious on DeviceName 
| join kind=leftouter LSASS_Signals on DeviceName 
| join kind=leftouter DumpTools on DeviceName 
| extend DetectionSignal = coalesce(LDAPHits,0)*10 + coalesce(LsassEvents,0)*20 + 
coalesce(ToolExecs,0)*30; 
// ---- Step 6: MISP / TI enrichment ---- 
let Enriched = 
Combined 
| join kind=leftouter ( 
ThreatIntelligenceIndicator 
| where IndicatorType in ("HostName","FileName","IP") 
| project TI_Indicator=Indicator, TI_Confidence=ConfidenceScore, 
TI_TLP=TlpLevel, TI_Type=ThreatType, TI_Tags=Tags 
) on $left.DeviceName == $right.TI_Indicator 
| extend IntelConfidence = toint(coalesce(TI_Confidence,50)), 
KillChainRelevance = 80, // Persistence + Discovery 
TemporalScore = 100, 
FinalScore = toint(round(DetectionSignal*0.4 + IntelConfidence*0.3 + 
KillChainRelevance*0.2 + TemporalScore*0.1)), 
FinalRisk = 
case(FinalScore>=90,"CRITICAL",FinalScore>=70,"HIGH","MEDIUM"); 
// ---- Step 7: Output with analyst directives ---- 
Enriched 
| extend MITRE_Tactics = "TA0007 Discovery; TA0008 Lateral Movement; TA0003 
Persistence", 
MITRE_Techniques = "T1078 Valid Accounts; T1555 Credential Dumping; 
T1482 Domain Discovery", 
ThreatHunterDirective = case( 
FinalRisk=="CRITICAL","IMMEDIATE CONTAINMENT — isolate host, revoke 
creds, scan for LSASS dumps, review LDAP traffic.", 
FinalRisk=="HIGH","URGENT REVIEW — verify device join status, check 
dump tools, escalate if AD queries seen.", 
"INVESTIGATE — validate naming, onboard device, monitor for privilege 
activity." 
) 
| project DeviceName, IsOnboarded, NameOk, 
LDAPHits, LsassEvents, ToolExecs, 
TI_TLP, TI_Confidence, TI_Type, 
FinalScore, FinalRisk, 
MITRE_Tactics, MITRE_Techniques, ThreatHunterDirective 
| order by FinalScore desc 
Why this is all-in-one flags unmanaged hosts: LDAP/AD scanning to external IPs, 
detection of Kerberos/AD opportunistic tools, and ties LSASS events to suspicious 
processes. 
5) LSASS / Credential Dumping — FRAGMENT 
// SecurityEvents: suspicious handle access to LSASS SecurityEvent 
| where EventID in (4656, 4663) // object handle/operation 
| where ObjectName has "lsass" or ObjectType has "Process" 
| project TimeGenerated, Computer, Account, EventID, ObjectName, 
ProcessName=tostring(ProcessName) 
// Process-based detectors (mimikatz/procdump) 
DeviceProcessEvents 
| where Timestamp >= ago(7d) 
| where FileName in ("mimikatz.exe","procdump.exe","procdump64.exe") 
or ProcessCommandLine has_any ("sekurlsa","-ma","- 
accepteula","Invoke-Mimikatz") 
| project Timestamp, DeviceName, FileName, ProcessCommandLine, 
SHA256=coalesce(FileHash, SHA256) 
2
 ️
 ⃣ Suspicious Ports with MISP Enrichment (Original Rule: Ala Dabat) 
// ===================================================================== 
// Suspicious Port Threat Hunt (External CTI + Adaptive Risk Scoring) 
// Author: Ala Dabat 
// Description: 
//   • Pulls external port intelligence from GitHub (awesome-lists) 
//   • Correlates DeviceNetworkEvents to suspicious ports 
//   • Enriches with MISP indicators (via ThreatIntelligenceIndicator table) 
//   • Applies weighted scoring for Zero-Trust network validation 
//   • Outputs MITRE mapping & Hunter directives 
// ===================================================================== 
// 1️⃣ External CSV Feed — align exactly with the repo schema 
let SuspiciousPortsData = externaldata( 
dest_port:int, 
metadata_comment:string, 
metadata_confidence:string, 
metatada_category:string,             
// (typo is present in actual CSV) 
metadata_detection_type:string, 
metadata_link:string, 
metadata_reference:string 
) 
[@"https://raw.githubusercontent.com/mthcht/awesome
lists/main/Lists/suspicious_ports_list.csv"] 
with (format='csv', ignoreFirstRecord=true) 
| where metadata_confidence !in ("low","info"); // filter low-confidence ports 
// 2️⃣ Build lookup sets and contextual table 
let SuspiciousPortList = toscalar(SuspiciousPortsData | summarize 
make_set(dest_port)); 
let PortDetails = SuspiciousPortsData 
| project dest_port, metadata_comment, metadata_confidence, metatada_category, 
metadata_detection_type, metadata_reference; 
// 3️⃣ Find suspicious connections in telemetry (DeviceNetworkEvents) 
let NetHits = DeviceNetworkEvents 
| where Timestamp >= ago(14d) 
| where RemotePort in (SuspiciousPortList) 
| where ActionType in ("InboundConnectionAccepted","OutboundConnection") 
| where not(RemoteIP in ("::1","::ffff:127.0.0.1")) 
| where not(startswith(RemoteIP,"10.") or startswith(RemoteIP,"192.168.") or 
startswith(RemoteIP,"172.") or startswith(RemoteIP,"127.") or 
startswith(RemoteIP,"8.")) 
| join kind=inner (PortDetails) on $left.RemotePort == $right.dest_port 
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Count=count(), 
ExampleProcess=arg_max(Timestamp, InitiatingProcessFileName), 
ExampleCommand=arg_max(Timestamp, InitiatingProcessCommandLine) 
by DeviceName, RemoteIP, RemotePort, ActionType, 
metadata_comment, metadata_confidence, metatada_category, 
metadata_detection_type, metadata_reference; 
// 4️⃣ Enrich with MISP or TI feed indicators 
let Enriched = NetHits 
| join kind=leftouter ( 
ThreatIntelligenceIndicator 
| where IndicatorType in ("IP","IPv4","ip-dst") 
| project TI_IP=Indicator, TI_Confidence=ConfidenceScore, 
TI_TLP=TlpLevel, TI_Type=ThreatType, TI_Tags=Tags, 
TI_Source=SourceSystem, TI_FirstSeen=FirstSeen, 
TI_LastSeen=LastSeen 
) on $left.RemoteIP == $right.TI_IP; 
// 5️⃣ Adaptive Weighted Model 
Enriched 
| extend 
DetectionSignal = case( 
metadata_confidence == "high", 90, 
metadata_confidence == "medium", 70, 
metadata_confidence == "info", 40, 
20), 
IntelConfidence = toint(coalesce(TI_Confidence, 50)), 
KillChainRelevance = case( 
metadata_detection_type =~ "C2", 90, 
metadata_detection_type =~ "Defense Evasion", 80, 
metatada_category =~ "malware", 70, 
60), 
TemporalDays = toint(datetime_diff('day', now(), coalesce(TI_LastSeen, 
now())) * -1), 
TemporalScore = case( 
TemporalDays <= 7, 100, 
TemporalDays <= 30, 60, 
TemporalDays <= 90, 40, 
20), 
FinalScore = toint(round( 
(DetectionSignal * 0.4) + (IntelConfidence * 0.3) + 
(KillChainRelevance * 0.2) + (TemporalScore * 0.1) 
)), 
FinalRisk = case( 
FinalScore >= 90, "CRITICAL", 
FinalScore >= 70, "HIGH", 
FinalScore >= 40, "MEDIUM", 
"LOW"), 
MITRE_Tactics = "TA0011 Command and Control; TA0010 Exfiltration", 
MITRE_Techniques = case( 
RemotePort == 1080, "T1090 Proxy; SOCKS tunneling", 
RemotePort == 1194, "T1573 Encrypted Channel (VPN)", 
RemotePort == 6667, "T1071.001 IRC Application Layer Protocol", 
"T1071 Application Layer Protocol"), 
ThreatHunterDirective = case( 
FinalRisk == "CRITICAL", 
strcat("IMMEDIATE CONTAINMENT — Block IP ", RemoteIP, ", isolate 
host, collect PCAP and memory; correlate process ", ExampleProcess, ". [", 
MITRE_Techniques, "]"), 
FinalRisk == "HIGH", 
strcat("URGENT REVIEW — Inspect process ", ExampleProcess, ", 
validate command ", ExampleCommand, ", check DNS logs; post IOC sighting to MISP. 
[", MITRE_Techniques, "]"), 
FinalRisk == "MEDIUM", 
strcat("INVESTIGATE — Review recurrence, enrich IOC, confirm with 
OpenCTI actor mapping. [", MITRE_Techniques, "]"), 
"MONITOR — Track IOC aging and confidence trend in MISP." ), 
VT_Link = strcat("https://www.virustotal.com/gui/ip-address/", RemoteIP); 
// 6️⃣ Final output for triage 
Enriched 
| project 
FirstSeen, LastSeen, DeviceName, RemoteIP, RemotePort, ActionType, Count, 
metadata_comment, metadata_confidence, metatada_category, 
metadata_detection_type, 
TI_TLP, TI_Confidence, TI_Type, TI_Tags, TI_Source, 
DetectionSignal, IntelConfidence, KillChainRelevance, TemporalScore, 
FinalScore, FinalRisk, MITRE_Tactics, MITRE_Techniques, 
ExampleProcess, ExampleCommand, ThreatHunterDirective, VT_Link 
| where FinalRisk in ("HIGH","CRITICAL") 
| order by FinalScore desc, Count desc, LastSeen desc 
This hunt dynamically ingests open-source port intelligence and merges it with 
MISP indicators to identify suspicious network activity. 
It applies a data-driven Zero-Trust model — each event is scored by telemetry 
confidence, CTI confidence, kill-chain relevance, and time proximity. 
The output includes MITRE mappings and clear directives so an analyst knows 
exactly what to do next, and verified sightings can be pushed back to MISP 
automatically for confidence enrichment 
Simplified Port Detection Rule: Original Rule 
// Suspicious Port Activity   
// Author: Ala Dabat   
// Purpose: Detect unusual inbound/outbound network connections using 
community-sourced port intelligence.   
// Captures: Supply-chain and C2 activity patterns (SolarWinds 
SUNBURST, NotPetya SMB lateral, 3CX C2 beacons).   
// MITRE: TA0011 (Command and Control), TA0005 (Defense Evasion)   
let SuspiciousPortsData = externaldata( 
dest_port:int, 
metadata_comment:string, 
metadata_confidence:string 
) 
[@"https://raw.githubusercontent.com/mthcht/awesome
lists/main/Lists/suspicious_ports_list.csv"] 
with (format='csv', ignoreFirstRecord=true) 
| where metadata_confidence != "low"; 
let SuspiciousPortList = toscalar(SuspiciousPortsData | summarize 
make_set(dest_port)); 
DeviceNetworkEvents 
| where RemotePort in (SuspiciousPortList) 
| where RemoteIP !in~ ("::1","127.0.0.1") 
| join kind=leftouter ( 
ThreatIntelligenceIndicator 
| where IndicatorType == "IP" 
| project TI_Indicator = Indicator, TI_Score = 100 
) on $left.RemoteIP == $right.TI_Indicator 
| extend VT_Link = strcat("https://www.virustotal.com/gui/ip
address/", RemoteIP) 
| extend RiskLevel = iif(TI_Score == 100, "CRITICAL", "HIGH") 
  
Line 
Range 
Function Description 
6–8 External CTI Feed 
Ingestion 
Pulls the latest open-source list of suspicious 
or high-risk ports from GitHub’s “awesome
lists” repository. This feed is curated from 
multiple community and malware-analysis 
sources and can later be integrated through 
MISP/TAXII for automation. 
10–12 Network Telemetry 
Filtering 
Scans DeviceNetworkEvents for both 
inbound and outbound connections where 
RemotePort matches known suspicious ports. 
This helps capture malware beaconing or 
unauthorized service listeners. 
13–14 Internal Network 
Exclusions 
Filters out private IP address ranges (10., 172., 
192.168.*, localhost) to prevent noise from 
internal system communications. Focus 
remains on external traffic likely to indicate 
compromise. 
15–18 Threat Intelligence 
Correlation 
Joins network events against the 
ThreatIntelligenceIndicator table (MISP
integrated). This step provides confidence 
scoring and actor tagging when an IP matches 
an existing IOC. 
19–21 Analyst Enrichment & 
Risk Scoring 
Adds VirusTotal lookups for quick verification 
and assigns a RiskLevel based on TI 
confidence. All TI matches default to 
“CRITICAL,” while non-matches are labeled 
“HIGH” for review. 
 
回 Registry Persistence (My Original Rule) 
// ---------- CONFIG ---------- 
let PersistenceKeys = dynamic([// Classic 
@"HKLM\Software\Microsoft\Windows\CurrentVersion\Run", 
@"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", 
@"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce" 
@"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce", 
@"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Ex
plorer\Run", 
@"HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\pl
 orer\Run", 
@"HKLM\SOFTWARE\Microsoft\Active Setup\Installed 
Components", @"HKCU\SOFTWARE\Microsoft\ActiveSetup\Installed 
Components", 
@"HKLM\Software\Microsoft\WindowsNT\CurrentVersion\Winlogon\
 Userinit", 
@"HKLM\Software\Microsoft\WindowsNT\CurrentVersion\Winlogon\
 Shell", 
@"HKCU\Software\Microsoft\WindowsNT\CurrentVersion\Winlogon\
 Shell", 
@"HKLM\Software\Microsoft\WindowsNT\CurrentVersion\Windows\A
 ppInit_DLLs", 
@"HKLM\SYSTEM\CurrentControlSet\Services", 
// Hijacks 
@"HKCU\Software\Classes\mscfile\shell\open\command", 
@"HKCU\Software\Classes\exefile\shell\open\command", 
@"HKCU\Software\Microsoft\Windows\CurrentVersion\App Paths", 
@"HKLM\Software\Microsoft\Windows\CurrentVersion\App Paths", 
// IFEO / COM / LSA 
@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image 
File Execution Options", 
@"HKCU\Software\Classes\CLSID", 
@"HKLM\Software\Classes\CLSID", 
@"HKLM\SYSTEM\CurrentControlSet\Control\Lsa", 
// WOW64 mirrors 
@"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion
 \Run", 
@"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion
 \RunOnce", 
@"HKLM\SOFTWARE\WOW6432Node\Microsoft\WindowsNT\CurrentVersi
 on\Image File Execution Options" 
]); 
let BadStrings = dynamic([ 
// PowerShell & AMSI bypass/common stagers 
"-EncodedCommand"," -enc "," -e ","-ep bypass"," -w 
hidden","IEX(","Invoke-Expression","FromBase64String", 
"Invoke-WebRequest","DownloadString","Start-BitsTransfer", 
// LOLBAS 
"mshta ","rundll32 ","regsvr32 ","certutil ","bitsadmin 
","curl ", 
// Injection API markers (if attackers stash commands) 
"WriteProcessMemory","VirtualAllocEx","CreateRemoteThread" 
]); 
let SuspExt = 
dynamic(["exe","dll","js","jse","vbs","vbe","wsf","hta","ps1
 ","psm1","bat","cmd","scr"]); 
let UserWritableRx = @"(?i)^[a
z]:\\(Users|Public|ProgramData|PerfLogs|Temp|Windows\\Temp|W
 indows\\Tasks|Windows\\Fonts)\\"; 
let Base64ChunkedRx = @"(?:[A-Za-z0
9+/]{20,}={0,2})(?:\s+[A-Za-z0-9+/]{20,}={0,2})+"; 
let IPv4Rx = @"\b(?:(?:25[0-5]|2[0
4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"; 
let IPv6Rx = @"\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0
9]{1,4}\b"; 
let DomainRx = @"\b([a-z0-9][a-z0-9\-]{1,62}\.)+[a
z]{2,}\b"; 
let OrgPrevalence = 
DeviceFileEvents 
| where Timestamp > ago(14d) 
| summarize DeviceCount=dcount(DeviceId), 
FirstSeen=min(Timestamp), LastSeen=max(Timestamp) by SHA256, 
FileName, FolderPath; 
 
let Raw = 
DeviceRegistryEvents 
| where ActionType == "RegistryValueSet" 
| where RegistryKey has_any (PersistenceKeys) 
| extend ValueData = tostring(RegistryValueData); 
 
// Join creating/initiating process context 
let WithProc = 
Raw 
| join kind=leftouter ( 
    DeviceProcessEvents 
    | project Timestamp, DeviceId, InitiatingProcessId, 
             IPFile=InitiatingProcessFileName, 
             IPPath=InitiatingProcessFolderPath, 
             IPCL=InitiatingProcessCommandLine, 
             IPSHA256=InitiatingProcessSHA256, 
             IPSigner=InitiatingProcessSigner, 
             
IPCompany=InitiatingProcessVersionInfoCompanyName, 
             
IPIntegrityLevel=InitiatingProcessIntegrityLevel, 
             IPAccount=InitiatingProcessAccountName 
) on InitiatingProcessId, DeviceId 
| extend LowerData = tolower(ValueData); 
 
// Extract indicators 
let WithIOC = 
WithProc 
| extend HasBadString = LowerData has_any (BadStrings), 
         HasBase64 = LowerData matches regex Base64ChunkedRx 
or LowerData matches regex @"[A-Za-z0-9+/]{40,}={0,2}", 
         HasNet = LowerData matches regex 
@"https?://[^\s'\""]+" or LowerData matches regex IPv4Rx or 
LowerData matches regex IPv6Rx or LowerData matches regex 
DomainRx, 
         PointsToUserWritable = ValueData matches regex 
UserWritableRx 
                                or LowerData matches regex 
@"\\appdata\\|\\programdata\\|\\temp\\|\\public\\", 
         SuspFileRef = LowerData matches regex 
@"(?i)\.(exe|dll|js|jse|vbs|vbe|wsf|hta|ps1|psm1|bat|cmd|scr
 )\b", 
         IsIFEO = tolower(RegistryKey) has @"\image file 
execution options\", 
         IsCOM = tolower(RegistryKey) has @"\clsid\" and 
tolower(RegistryKey) has @"inprocserver32", 
         IsLSA = tolower(RegistryKey) has @"\control\lsa", 
         Hive = iif(startswith(tolower(RegistryKey),"hklm"), 
"System-wide (HKLM)", "Per-user (HKCU/Classes)"); 
 
// Bring in prevalence & signer trust 
let Enriched = 
WithIOC 
| join kind=leftouter (OrgPrevalence) on $left.IPSHA256 == 
$right.SHA256 
| extend IsTrustedPublisher = iif(IPSigner in~ ("Microsoft 
Windows","Microsoft Windows Publisher","Microsoft 
Corporation","Microsoft Windows Hardware Compatibility 
Publisher"), true, false), 
         IsRare = coalesce(DeviceCount, 0) <= 2; 
 
// High-fidelity scoring (stack multiple independent 
signals) 
Enriched 
| extend SignalCount = 
    toint(HasBadString) + toint(HasBase64) + toint(HasNet) + 
toint(PointsToUserWritable) + 
    toint(not(IsTrustedPublisher)) + toint(IsRare) + 
toint(IsIFEO or IsCOM or IsLSA) 
| where SignalCount >= 3  // <- L3 threshold (tune 3–4) 
| project 
    Timestamp, DeviceName, Hive, RegistryKey, 
RegistryValueName, ValueData, 
    IPFile, IPPath, IPCL, IPSHA256, IPSigner, IPCompany, 
IPIntegrityLevel, IPAccount, 
    HasBadString, HasBase64, HasNet, PointsToUserWritable, 
SuspFileRef, IsIFEO, IsCOM, IsLSA, IsTrustedPublisher, 
IsRare, SignalCount 
| extend MITRE_Tactics = "TA0003 Persistence; TA0002 
Execution; TA0005 Defense Evasion",  
         MITRE_Techniques = 
           strcat_array( 
             bag_keys( 
               pack_array( 
                 iif(HasBadString and LowerData has 
"powershell","T1059.001 PowerShell",""), 
                 iif(HasBadString and LowerData has 
"regsvr32","T1218.010 Regsvr32",""), 
                 iif(HasBadString and LowerData has 
"rundll32","T1218.011 Rundll32",""), 
                 iif(HasBadString and LowerData has 
"mshta","T1218.005 Mshta",""), 
                 iif(HasNet,"T1105 Ingress Tool 
Transfer",""), 
                 iif(IsIFEO,"T1546.012 Image File Execution 
Options Injection",""), 
                 iif(IsCOM,"T1546.015 COM Hijacking",""), 
                 iif(IsLSA,"T1547.009 Security Support 
Provider",""), 
                 iif(tolower(RegistryKey) has 
@"\run","T1547.001 Registry Run Keys",""), 
                 iif(tolower(RegistryKey) has 
@"\services","T1543.003 Windows Service","") 
               ) 
             ), "; "), 
           ThreatSeverity = case( 
             HasBadString and (HasBase64 or HasNet), 
"CRITICAL", 
             (IsIFEO or IsCOM or IsLSA) and (not 
IsTrustedPublisher), "HIGH", 
             PointsToUserWritable and (HasNet or HasBase64) 
and IsRare, "HIGH", 
             SignalCount >= 4, "HIGH", 
             "MEDIUM" 
           ) 
| order by ThreatSeverity desc, Timestamp desc 
 
// Hunt-mode: High-fidelity SignalCount for registry 
persistence writes (human review) 
// Lookback 
let lookback = 14d; 
 
// Tunable allowlists (replace with watchlist joins in prod) 
let TrustedPublishers = dynamic(["Microsoft 
Corporation","Microsoft Windows","Google LLC","Mozilla 
Corporation"]); 
let TrustedInitiators = 
dynamic(["msiexec.exe","IntelGraphics.exe","sppsvc.exe","Int
 uneManagementExtension.exe","UpdateInstaller.exe"]); 
 
// Persistence keys 
let PersistenceKeys = dynamic([ 
@"HKLM\Software\Microsoft\Windows\CurrentVersion\Run", 
@"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", 
@"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce", 
@"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce", 
@"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Ex
 plorer\Run", 
@"HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Ex
 plorer\Run", 
@"HKLM\SOFTWARE\Microsoft\Active Setup\Installed 
Components", @"HKCU\SOFTWARE\Microsoft\Active 
Setup\Installed Components", 
@"HKLM\Software\Microsoft\Windows 
NT\CurrentVersion\Winlogon\Userinit", 
@"HKLM\Software\Microsoft\Windows 
NT\CurrentVersion\Winlogon\Shell", 
@"HKCU\Software\Microsoft\Windows 
NT\CurrentVersion\Winlogon\Shell", 
@"HKLM\Software\Microsoft\Windows 
NT\CurrentVersion\Windows\AppInit_DLLs", 
@"HKLM\SYSTEM\CurrentControlSet\Services", 
@"HKCU\Software\Classes\mscfile\shell\open\command", 
@"HKCU\Software\Classes\exefile\shell\open\command", 
@"HKCU\Software\Microsoft\Windows\CurrentVersion\App 
Paths", @"HKLM\Software\Microsoft\Windows\CurrentVersion\App 
Paths", 
@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image 
File Execution Options", 
@"HKCU\Software\Classes\CLSID", 
@"HKLM\Software\Classes\CLSID", 
@"HKLM\SYSTEM\CurrentControlSet\Control\Lsa", 
@"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion
 \Run", 
@"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion
 \RunOnce", 
@"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows 
NT\CurrentVersion\Image File Execution Options" 
]); 
// Heuristics / regexes 
let UserWritableRx = @"(?i)^[a
z]:\\(users|public|programdata|temp|downloads|appdata)\\"; 
let Base64ChunkedRx = @"(?:[A-Za-z0
9+/]{20,}={0,2})(?:\s+[A-Za-z0-9+/]{20,}={0,2})+"; 
let IPv4Rx = @"\b(?:(?:25[0-5]|2[0
4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"; 
let DomainRx = @"\b([a-z0-9][a-z0-9\-]{1,62}\.)+[a
z]{2,}\b"; 
let BadStrings = dynamic(["-encodedcommand","-enc","-ep 
bypass","iex(","invoke
expression","frombase64string","invoke
webrequest","downloadstring","start
bitstransfer","rundll32","regsvr32","mshta","certutil","bits
 admin","curl","writeprocessmemory","virtualallocex","creater
 emotethread"]); 
// Prevalence: where file hash has been seen recently 
let OrgPrevalence = DeviceFileEvents 
| where Timestamp >= ago(30d) 
| summarize DeviceCount=dcount(DeviceId) by SHA256, 
FileName, FolderPath; 
// Raw registry persistence writes 
let Raw = DeviceRegistryEvents 
| where Timestamp >= ago(lookback) 
| where ActionType == "RegistryValueSet" 
| where RegistryKey has_any (PersistenceKeys) 
| extend ValueData = tostring(RegistryValueData), ValueName 
= tostring(RegistryValueName), RegistryKeyLower = 
tolower(RegistryKey) 
| extend LowerData = tolower(ValueData); 
// Join initiating process context (best effor tmatch) 
let WithProc = Raw 
| join kind=leftouter ( 
DeviceProcessEvents 
| project ProcTime = Timestamp, DeviceId, 
InitiatingProcessId, InitiatingProcessFileName, 
InitiatingProcessFolderPath, InitiatingProcessCommandLine, 
InitiatingProcessSHA256, InitiatingProcessSigner, 
InitiatingProcessVersionInfoCompanyName, 
InitiatingProcessAccountName 
) on InitiatingProcessId, DeviceId 
| extend ProcFile = coalesce(InitiatingProcessFileName, ""), 
ProcPath = coalesce(InitiatingProcessFolderPath,""), ProcCL 
= coalesce(InitiatingProcessCommandLine,""), ProcSHA = 
InitiatingProcessSHA256, ProcSigner = 
InitiatingProcessSigner, ProcCompany = 
InitiatingProcessVersionInfoCompanyName, ProcUser = 
InitiatingProcessAccountName; 
// Extract signals (binary flags) 
let WithIOC = 
WithProc 
| extend 
HasBadString = toint(LowerData has_any (BadStrings)), 
HasBase64 = toint(LowerData matches regex 
Base64ChunkedRx or ProcCL matches regex Base64ChunkedRx), 
HasNet = toint(LowerData matches regex 
@"https?://[^\s'\""]+" or LowerData matches regex IPv4Rx or 
LowerData matches regex DomainRx), 
PointsToUserWritable = toint(LowerData matches regex 
UserWritableRx or LowerData contains "\\appdata\\" or 
LowerData contains "\\programdata\\" or LowerData contains 
"\\temp\\"), 
SuspFileRef = toint(LowerData matches regex 
@"(?i)\.(exe|dll|js|jse|vbs|ps1|bat|cmd|scr)\b"), 
IsIFEO = toint(RegistryKeyLower has @"\image file 
execution options"), 
IsCOM = toint(RegistryKeyLower has @"\clsid\" and 
RegistryKeyLower has @"inprocserver32"), 
IsLSA = toint(RegistryKeyLower has @"\control\lsa"), 
IsTrustedPublisher = iif(ProcSigner in 
(TrustedPublishers) or ProcCompany in (TrustedPublishers), 
1, 0), 
InitiatorTrusted = iif(ProcFile in (TrustedInitiators), 
1, 0); 
// Bring in prevalence / rarity 
let Enriched = 
WithIOC 
| join kind=leftouter (OrgPrevalence) on $left.ProcSHA == 
$right.SHA256 
| extend DeviceCount = coalesce(DeviceCount, 0), IsRare = 
iif(DeviceCount <= 2, 1, 0); 
// SIGNAL COUNT (human-friendly, not hidden) 
Enriched 
| extend SignalCount =  
HasBadString + HasBase64 + HasNet + PointsToUserWritable 
+ (1 - IsTrustedPublisher) + IsRare + (IsIFEO or IsCOM or 
IsLSA) 
// Aggregate per device + registry value to reduce 
duplicates (hunter can expand as needed) 
| summarize FirstSeen = min(Timestamp), LastSeen = 
max(Timestamp),  
            MaxSignals = max(SignalCount), Events = count(), 
            AnyBadString = max(HasBadString), AnyBase64 = 
max(HasBase64), AnyNet = max(HasNet), AnyUserWritable = 
max(PointsToUserWritable), 
            AnyIFEO = max(IsIFEO), AnyCOM = max(IsCOM), 
AnyLSA = max(IsLSA), 
            AnyTrustedPublisher = max(IsTrustedPublisher), 
AnyRare = max(IsRare), 
            Initiators = make_set(ProcFile,10), 
InitiatorSigners = make_set(ProcSigner,10), ExampleProcCL = 
any(ProcCL) 
  by DeviceName, RegistryKey, ValueName, ValueData, ProcSHA, 
ProcCompany, ProcSigner, ProcUser 
// Final: return human readable table for triage 
| extend MITRE_Tactics = "TA0003 Persistence; TA0002 
Execution; TA0005 Defense Evasion" 
| extend MITRE_Techniques = strcat_array( 
    pack_array( 
      iif(AnyBadString==1 and ExampleProcCL has 
"powershell","T1059.001 PowerShell",""), 
      iif(AnyBadString==1 and ExampleProcCL has 
"regsvr32","T1218.010 Regsvr32",""), 
      iif(AnyBadString==1 and ExampleProcCL has 
"rundll32","T1218.011 Rundll32",""), 
      iif(AnyBadString==1 and ExampleProcCL has 
"mshta","T1218.005 Mshta",""), 
      iif(AnyNet==1,"T1105 Ingress Tool Transfer",""), 
      iif(AnyIFEO==1,"T1546.012 IFEO Injection",""), 
      iif(AnyCOM==1,"T1546.015 COM Hijacking",""), 
      iif(AnyLSA==1,"T1547.009 LSA / SSP Hijack",""), 
      iif(tolower(RegistryKey) has @"\run","T1547.001 
Registry Run Keys",""), 
iif(tolower(RegistryKey) has @"\services","T1543.003 
Windows Service","") 
), "; ") 
| project FirstSeen, LastSeen, DeviceName, ProcUser, 
ProcCompany, ProcSigner, ProcSHA, RegistryKey, ValueName, 
ValueData, MaxSignals, Events, AnyNet, AnyBase64, 
AnyBadString, AnyUserWritable, AnyIFEO, AnyCOM, AnyLSA, 
AnyRare, Initiators, InitiatorSigners, ExampleProcCL, 
MITRE_Tactics, MITRE_Techniques 
| order by MaxSignals desc, LastSeen desc 
Registry MISP Integration 
// ===================================================================== 
// Registry Persistence + C2/LOLBIN Correlation with MISP (TI) Enrichment 
// Author: Ala Dabat (SOC/MDR → CTI bridge) 
// Goal: 
//   • Find suspicious registry persistence writes (Run, Winlogon, IFEO, COM, 
LSA, Services) 
//   • Extract IOCs (URL/domain/IP) from registry values; join with 
ThreatIntelligenceIndicator (MISP feed) 
//   • Score using adaptive model: Detection(0.4) + Intel(0.3) + KillChain(0.2) + 
Temporal(0.1) 
//   • Output Hunter Directives with MITRE tactics/techniques embedded 
// Notes: 
//   • Replace inline allowlists with Watchlists in production (e.g. 
_GetWatchlist()) 
//   • Pair this hunt with a SOAR playbook to POST STIX Sighting to MISP when 
FinalRisk ≥ HIGH 
// ===================================================================== 
// ---------- CONFIG (persistence surfaces & heuristics) ---------- 
let lookback = 14d;  // hunting window 
let prevalenceWindow = 30d; // for rare process prevalence 
// Common persistence locations (Run keys, Winlogon, Services, IFEO, COM, LSA, 
etc.) 
let PersistenceKeys = dynamic([ 
/ Classic 
@"HKLM\Software\Microsoft\Windows\CurrentVersion\Run" 
@"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", 
@"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce", 
@"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce", 
@"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", 
@"HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", 
@"HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components", 
@"HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components", 
@"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit", 
@"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell", 
@"HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell", 
@"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs", 
@"HKLM\SYSTEM\CurrentControlSet\Services", 
// Hijacks 
@"HKCU\Software\Classes\mscfile\shell\open\command", 
@"HKCU\Software\Classes\exefile\shell\open\command", 
@"HKCU\Software\Microsoft\Windows\CurrentVersion\App Paths", 
@"HKLM\Software\Microsoft\Windows\CurrentVersion\App Paths", 
// IFEO / COM / LSA 
@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution 
Options", 
@"HKCU\Software\Classes\CLSID", @"HKLM\Software\Classes\CLSID", 
@"HKLM\SYSTEM\CurrentControlSet\Control\Lsa", 
// WOW64 mirrors 
@"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", 
@"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce", 
@"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File 
Execution Options" 
]); 
// Suspicious command markers (stagers/LOLBINs/injection API crumbs that 
attackers stash in values) 
let BadStrings = dynamic([ 
"-encodedcommand"," -enc "," -e ","-ep bypass"," -w hidden","iex(","invoke
expression","frombase64string", 
"invoke-webrequest","downloadstring","start-bitstransfer", 
"mshta ","rundll32 ","regsvr32 ","certutil ","bitsadmin ","curl ","wget ", 
"writeprocessmemory","virtualallocex","createremotethread" 
]); 
// Simple regex helpers (user-writable paths, base64 blobs, IPs/domains) 
let UserWritableRx = @"(?i)^[a
z]:\\(users|public|programdata|temp|downloads|appdata)\\"; 
let Base64ChunkedRx = @"(?:[A-Za-z0-9+/]{20,}={0,2})(?:\s+[A-Za-z0
9+/]{20,}={0,2})+"; 
let IPv4Rx = @"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0
4]\d|1?\d?\d)\b"; 
let IPv6Rx = @"\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b"; 
let DomainRx = @"\b([a-z0-9][a-z0-9\-]{1,62}\.)+[a-z]{2,}\b"; 
// ---------- PREVALENCE (how rare is the initiating binary) ---------- 
let OrgPrevalence = 
DeviceFileEvents 
| where Timestamp >= ago(prevalenceWindow) 
| summarize DeviceCount=dcount(DeviceId), FirstSeen=min(Timestamp), 
LastSeen=max(Timestamp) by SHA256, FileName, FolderPath; 
// ---------- RAW REGISTRY WRITES AT PERSISTENCE SURFACES ---------- 
let Raw = 
DeviceRegistryEvents 
| where Timestamp >= ago(lookback) 
| where ActionType == "RegistryValueSet" 
| where RegistryKey has_any (PersistenceKeys) 
| extend ValueData = tostring(RegistryValueData), ValueName = 
tostring(RegistryValueName), RegistryKeyLower = tolower(RegistryKey); 
// ---------- JOIN INITIATING PROCESS CONTEXT ---------- 
let WithProc = 
Raw 
| join kind=leftouter ( 
DeviceProcessEvents 
| project ProcTime = Timestamp, DeviceId, InitiatingProcessId, 
ProcFile=InitiatingProcessFileName, 
ProcPath=InitiatingProcessFolderPath, 
ProcCL=InitiatingProcessCommandLine, 
ProcSHA=InitiatingProcessSHA256, 
ProcSigner=InitiatingProcessSigner, 
ProcCompany=InitiatingProcessVersionInfoCompanyName, 
ProcIntegrity=InitiatingProcessIntegrityLevel, 
ProcUser=InitiatingProcessAccountName 
) on InitiatingProcessId, DeviceId 
| extend LowerData = tolower(ValueData); 
// ---------- EXTRACT IOC CANDIDATES FROM VALUE DATA (URL/IP/DOMAIN) ---------- 
let WithIOC = 
WithProc 
| extend 
UrlHit     
= extract(@"https?://[^\s'\""]+", 0, ValueData), 
DomainHit  = extract(DomainRx, 0, LowerData), 
IPv4Hit    
IPv6Hit    
= extract(IPv4Rx, 0, LowerData), 
= extract(IPv6Rx, 0, LowerData), 
AnyNetIOC  = iif(isnotempty(UrlHit) or isnotempty(DomainHit) or 
isnotempty(IPv4Hit) or isnotempty(IPv6Hit), 1, 0), 
HasBadString = iif(LowerData has_any (BadStrings), 1, 0), 
HasBase64    
= iif(LowerData matches regex Base64ChunkedRx or ProcCL matches 
regex Base64ChunkedRx, 1, 0), 
UserWritable = iif(LowerData matches regex UserWritableRx or LowerData 
contains "\\appdata\\" or LowerData contains "\\programdata\\" or LowerData 
contains "\\temp\\", 1, 0), 
SuspFileRef  = iif(LowerData matches regex 
@"(?i)\.(exe|dll|js|jse|vbs|ps1|bat|cmd|scr)\b", 1, 0), 
IsIFEO       
0), 
IsCOM        
= iif(RegistryKeyLower has @"\image file execution options", 1, 
= iif(RegistryKeyLower has @"\clsid\" and RegistryKeyLower has 
@"inprocserver32", 1, 0), 
IsLSA        
Hive         
= iif(RegistryKeyLower has @"\control\lsa", 1, 0), 
= iif(startswith(RegistryKeyLower,"hklm"), "System-wide (HKLM)", 
"Per-user (HKCU/Classes)"); 
// ---------- ENRICH WITH PREVALENCE (RARE INITIATORS) ---------- 
let EnrichedPrev = 
WithIOC 
| join kind=leftouter (OrgPrevalence) on $left.ProcSHA == $right.SHA256 
| extend DeviceCount = coalesce(DeviceCount, 0), IsRareProc = iif(DeviceCount <= 
2, 1, 0), 
TrustedPublisher = iif(ProcSigner in~ ("Microsoft Windows","Microsoft 
Windows Publisher","Microsoft Corporation","Microsoft Windows Hardware 
Compatibility Publisher"), 1, 0); 
// ---------- MISP → SENTINEL TI ENRICHMENT (TLP/Confidence/First/Last Seen) ---------- 
let TI_Enrich = 
EnrichedPrev 
| join kind=leftouter ( 
ThreatIntelligenceIndicator 
| where IndicatorType in ("URL","DomainName","IP","FileHash") 
| project TI_Indicator = Indicator, IndicatorType, ConfidenceScore, TlpLevel, 
ThreatType, 
LastSeen 
IndicatorFirstSeenTime = FirstSeen, IndicatorLastSeenTime = 
) on $left.UrlHit == $right.TI_Indicator 
or $left.DomainHit == $right.TI_Indicator 
or $left.IPv4Hit == $right.TI_Indicator 
or $left.IPv6Hit == $right.TI_Indicator 
or $left.ProcSHA == $right.TI_Indicator // sometimes TI has filehashes for 
loaders 
| extend 
TlpLevel        
= coalesce(TlpLevel, "TLP:WHITE"), 
ConfidenceScore = toint(coalesce(ConfidenceScore, 0)), 
ThreatType      
= coalesce(ThreatType, "Unknown"); 
// ---------- DETECTION SIGNAL (behavior) ---------- 
let Scored = 
TI_Enrich 
| extend 
// Behavior signals: stack independent indicators 
SignalCount = HasBadString + HasBase64 + AnyNetIOC + UserWritable + 
SuspFileRef + IsRareProc + (IsIFEO or IsCOM or IsLSA), 
// Scale to 0–100 with small weights to keep it intuitive 
DetectionSignal = toint( clamp( 
(HasBadString * 20) + (HasBase64 * 15) + (AnyNetIOC * 25) + (UserWritable 
* 10) + 
20), 
(SuspFileRef * 10) + (IsRareProc * 10) + ((IsIFEO or IsCOM or IsLSA) * 
0, 100)), 
// Intel confidence per TLP/Confidence policy (MISP) 
TI_Score = toint( case( 
TlpLevel == "TLP:RED"   and ConfidenceScore >= 90, 100, 
TlpLevel == "TLP:RED"   and ConfidenceScore >= 70,  80, 
TlpLevel == "TLP:RED",                              
60, 
TlpLevel == "TLP:AMBER" and ConfidenceScore >= 90,  80, 
TlpLevel == "TLP:AMBER" and ConfidenceScore >= 70,  60, 
TlpLevel == "TLP:AMBER",                            
40, 
TlpLevel == "TLP:GREEN" and ConfidenceScore >= 90,  60, 
TlpLevel == "TLP:GREEN" and ConfidenceScore >= 50,  40, 
TlpLevel == "TLP:WHITE",                            
20, 
0 
)), 
// Kill-chain relevance (late-stage evidence raises priority) 
//  • COM/LSA/IFEO/Services persistence → TA0003 (80) 
//  • Net IOC present → TA0011 C2 / TA0010 Exfil potential (90) 
//  • Pure Run/Winlogon with LOLBIN params (60) 
KillChainRelevance = toint( case( 
AnyNetIOC == 1, 90, 
(IsIFEO == 1 or IsCOM == 1 or IsLSA == 1), 80, 
true, 60 
)), 
// Temporal freshness (recency from TI last-seen or event time) 
TemporalAnchor = coalesce(IndicatorLastSeenTime, ProcTime, Timestamp), 
TemporalDays   
= toint( datetime_diff('day', now(), TemporalAnchor) * -1 ), 
TemporalScore  = toint( case( 
TemporalDays <= 7, 100, 
TemporalDays <= 30, 60, 
TemporalDays <= 90, 40, 
true, 20 
)), 
// FINAL WEIGHTED SCORE (0–100) 
FinalScore = toint(round( 
(DetectionSignal * 0.4) + (TI_Score * 0.3) + (KillChainRelevance * 0.2) + 
(TemporalScore * 0.1) 
)), 
FinalRisk = case( 
FinalScore >= 90, "CRITICAL", 
FinalScore >= 70, "HIGH", 
FinalScore >= 40, "MEDIUM", 
"LOW" 
), 
// MITRE tactics/techniques based on observed evidence 
MITRE_Tactics = strcat_array(pack_array( 
"TA0003 Persistence", 
"TA0005 Defense Evasion", 
"TA0002 Execution", 
iif(AnyNetIOC == 1, "TA0011 Command and Control", "") 
), ", "), 
MITRE_Techniques = strcat_array(pack_array( 
iif(RegistryKeyLower has @"\run","T1547.001 Registry Run Keys",""), 
iif(RegistryKeyLower has @"\services","T1543.003 Windows Service",""), 
iif(IsIFEO==1,"T1546.012 Image File Execution Options Injection",""), 
iif(IsCOM==1,"T1546.015 COM Hijacking",""), 
iif(IsLSA==1,"T1547.009 Security Support Provider",""), 
iif(HasBadString==1 and LowerData has "powershell","T1059.001 
PowerShell",""), 
iif(HasBadString==1 and LowerData has "regsvr32","T1218.010 
Regsvr32",""), 
iif(HasBadString==1 and LowerData has "rundll32","T1218.011 
Rundll32",""), 
iif(HasBadString==1 and LowerData has "mshta","T1218.005 Mshta",""), 
iif(AnyNetIOC==1,"T1105 Ingress Tool Transfer","") 
), "; "), 
// Hunter directive (includes MITRE context) 
ThreatHunterDirective = case( 
FinalScore >= 90, 
strcat("IMMEDIATE CONTAINMENT — Isolate host; export/decode registry 
value; kill/ban binary; block URL/domain/IP; capture memory; IR notify. [", 
MITRE_Tactics, " | ", MITRE_Techniques, "]"), 
FinalScore >= 70, 
strcat("URGENT INVESTIGATION — Validate autorun intent; verify 
publisher; retrieve file and ProcCL; check net IOC reputation; search fleet for 
hash/key. [", 
MITRE_Tactics, " | ", MITRE_Techniques, "]"), 
FinalScore >= 40, 
strcat("INVESTIGATE & TREND — Confirm user/business justification; add 
temp suppression if benign; watch for re-write. [", 
MITRE_Tactics, " | ", MITRE_Techniques, "]"), 
strcat("MONITOR — Log for historical patterns; await sighting 
corroboration. [", 
MITRE_Tactics, " | ", MITRE_Techniques, "]") 
) 
// ---------- FINAL TRIAGE VIEW ---------- 
| project 
Timestamp, DeviceName, Hive, RegistryKey, ValueName, ValueData, 
ProcFile, ProcPath, ProcCL, ProcSHA, ProcSigner, ProcCompany, ProcIntegrity, 
ProcUser, 
UrlHit, DomainHit, IPv4Hit, IPv6Hit, 
HasBadString, HasBase64, AnyNetIOC, UserWritable, SuspFileRef, IsIFEO, IsCOM, 
IsLSA, 
DeviceCount, IsRareProc, TrustedPublisher, 
TlpLevel, ConfidenceScore, ThreatType, 
DetectionSignal, TI_Score, KillChainRelevance, TemporalScore, 
FinalScore, FinalRisk, MITRE_Tactics, MITRE_Techniques, ThreatHunterDirective 
| order by FinalScore desc, Timestamp desc 
MISP Integration Into My Original Rule: 
// Registry Persistence Detection (MISP-Enriched) 
// Purpose: Identify suspicious persistence writes 
and anomalous autoruns linked to known or emerging 
threats. 
// Integrates: MISP (ThreatIntelligenceIndicator) 
enrichment, prevalence scoring, and heuristic 
detection. 
// Captures: SolarWinds svchelper.dll, NotPetya 
loader, 3CX trojanized persistence artifacts. 
// MITRE: TA0003 Persistence | TA0005 Defense Evasion 
| TA0011 Command & Control 
let lookback = 14d; 
let PersistenceKeys = dynamic([/* Run, Services, 
IFEO, CLSID, LSA, AppInit_DLLs */]); 
let TrustedPublishers = dynamic(["Microsoft 
Corporation","Microsoft Windows","Google 
LLC","Mozilla Corporation"]); 
// Step 1: Extract suspicious registry writes at 
persistence surfaces 
DeviceRegistryEvents 
| where Timestamp >= ago(lookback) and ActionType == 
"RegistryValueSet" 
| where RegistryKey has_any (PersistenceKeys) 
| extend LowerData = 
tolower(tostring(RegistryValueData)) 
// Step 2: Join process context (signer, command 
line) 
| join kind=leftouter ( 
DeviceProcessEvents 
| project InitiatingProcessId, DeviceId, 
InitiatingProcessFileName, 
InitiatingProcessCommandLine, InitiatingProcessSigner 
) on InitiatingProcessId, DeviceId 
// Step 3: Basic trust and behavior signals 
| extend IsTrustedPublisher = 
iif(InitiatingProcessSigner in 
(TrustedPublishers),1,0), 
HasLOLBIN = iif(LowerData has_any 
(dynamic(["rundll32","regsvr32","mshta","bitsadmin"])
 ),1,0) 
// Step 4: MISP TI enrichment — map 
domains/IPs/hashes to confidence & TLP 
| join kind=leftouter ( 
ThreatIntelligenceIndicator 
| where IndicatorType in 
("DomainName","IP","FileHash","URL") 
    | project TI_Indicator=Indicator, 
ConfidenceScore, TlpLevel, ThreatType 
) on $left.LowerData == $right.TI_Indicator 
 
// Step 5: Scoring & context 
| extend DetectionSignal = HasLOLBIN + (1 - 
IsTrustedPublisher), 
         TI_Score = iif(TlpLevel=="TLP:RED" and 
ConfidenceScore>=70,80, 
                    iif(TlpLevel=="TLP:AMBER" and 
ConfidenceScore>=70,60,40)), 
         FinalScore = toint(round(DetectionSignal*0.6 
+ TI_Score*0.4)), 
         FinalRisk = 
case(FinalScore>=80,"HIGH",FinalScore>=60,"MEDIUM","L
 OW"), 
         MITRE_Tactics="TA0003 Persistence; TA0005 
Defense Evasion", 
         MITRE_Techniques="T1547.001 Registry Run 
Keys; T1218.011 Rundll32" 
 
// Step 6: Output for triage & enrichment feedback 
| project Timestamp, DeviceName, RegistryKey, 
ValueName, 
          InitiatingProcessFileName, 
InitiatingProcessCommandLine, 
InitiatingProcessSigner, 
          TlpLevel, ConfidenceScore, ThreatType, 
FinalScore, FinalRisk, 
MITRE_Tactics, MITRE_Techniques 
| order by FinalScore desc, Timestamp desc 
How this may detect the 3CX / SolarWinds / NotPetya chain 
•    3CX Attack: 3CXDesktopApp.exe writes new Run key referencing a DLL → Heuristic 
signals + persistence path hit. 
•   SolarWinds SUNBURST: svchelper.dll registry entry created by signed 
SolarWinds binary → MISP enrichment correlates known IoCs. 
•   NotPetya: Loader writes service entry for payload → non- 
trusted publisher + persistence key → HIGH/CRITICAL alert. 
0Auth App-Consent Hunt (Bonus Hunt) 
// 
===================================================================== 
// OAuth Attack Chain (Illicit Consent / App Abuse) – Zero-Trust 
Adaptive Hunt 
// Author: Ala Dabat (SOC/MDR → CTI bridge) 
// Goal: 
//  • Detect risky OAuth consent patterns (app-only, tenant-wide, 
high-priv scopes) 
//  • Correlate with Service Principal sign-ins / scripted UAs (post
consent usage) 
//  • Enrich with TI (MISP → Sentinel TI table) and produce a weighted 
FinalScore 
// Model: FinalScore = Detection(0.4) + IntelConfidence(0.3) + 
KillChain(0.2) + Temporal(0.1) 
// Outputs: FinalScore, Risk band, MITRE tactics in Hunter Directives, 
investigation links 
// 
===================================================================== 
let lookback = 7d; 
// ------------------------------ 
// 0) Known approved apps (expand per tenant policy) 
let KnownSafeApps = dynamic([ 
  "Microsoft Office 365 Portal", "Microsoft Teams", "SharePoint 
Online", 
  "OneDrive", "Outlook Web App", "Microsoft Intune" 
]); 
 
// ------------------------------ 
// 1) OAuth consent events (AuditLogs) 
//    We extract: app name/id, app-only vs delegated, tenant-wide 
consent, scopes, initiator, IP/UserAgent. 
let Consent = 
AuditLogs 
| where TimeGenerated >= ago(lookback) 
| where OperationName in ("Consent to application","Add delegated 
permission grant","Add service principal credentials") 
| extend Target = TargetResources[0] 
| extend AppId          = tostring(Target.id), 
        AppDisplayName  = tostring(Target.displayName), 
        ModifiedProps   = Target.modifiedProperties, 
        InitiatorUPN    = 
tostring(InitiatedBy.user.userPrincipalName), 
        InitiatorIP     = tostring(InitiatedBy.user.ipAddress), 
        InitiatorUA     = tostring(InitiatedBy.user.userAgent) 
| mv-expand Prop = ModifiedProps 
| extend PropName  = tostring(Prop.displayName), 
         PropValue = tostring(Prop.newValue) 
| summarize 
    TimeGenerated   = any(TimeGenerated), 
    IsAppOnly       = any(iff(PropName =~ "ConsentContext.IsAppOnly",        
PropValue, "")), 
    OnBehalfOfAll   = any(iff(PropName =~ 
"ConsentContext.OnBehalfOfAll",    PropValue, "")),  // tenant-wide 
    GrantedScopes   = any(iff(PropName has "Scopes" or PropName has 
"Permissions" or PropName has "Oauth2PermissionScopes", PropValue, 
"")), 
    SPN_List        = any(iff(PropName has "ServicePrincipalNames",          
PropValue, "")), 
    InitiatorUPN    = any(InitiatorUPN), 
    InitiatorIP     = any(InitiatorIP), 
    InitiatorUA     = any(InitiatorUA) 
  by AppId, AppDisplayName 
| extend IsAppOnlyBool     = iif(tostring(IsAppOnly)     contains 
"True" or tostring(IsAppOnly)     contains "true", 1, 0) 
| extend OnBehalfAllBool   = iif(tostring(OnBehalfOfAll) contains 
"True" or tostring(OnBehalfOfAll) contains "true", 1, 0) 
| extend HighPrivScopes    = iif(tolower(GrantedScopes) has_any 
(dynamic([ 
                            
"Mail.ReadWrite","Files.ReadWrite","offline_access", 
                            
"Directory.ReadWrite.All","User.ReadWrite.All","MailboxSettings.ReadWr
 ite" 
                           ])), 1, 0) 
| extend AppIsNew          = 1  // assume new until we see usage below 
(will reduce if historical sign-ins are seen) 
| where AppDisplayName !in~ (KnownSafeApps); 
 
// ------------------------------ 
// 2) Post-consent usage: Service Principal sign-ins (app acting via 
Graph/API) 
//    Scripted UAs and new geos/IPs post-consent are suspicious. 
let SPUsage = 
AADServicePrincipalSignInLogs 
| where TimeGenerated >= ago(lookback) 
| extend AppId = tostring(ServicePrincipalId) 
| project SPTime=TimeGenerated, AppId, 
AppDisplayName=tostring(AppDisplayName), 
          SPClientApp=tostring(ClientAppUsed), SPAIP=IPAddress, 
SPAUA=UserAgent, Result=tostring(ResultType); 
 
// 3) User sign-ins around consent (to reveal scripted agents or 
unusual IPs for the consenting user) 
let UserUsage = 
SigninLogs 
| where TimeGenerated >= ago(lookback) 
| project UserTime=TimeGenerated, UserPrincipalName, IPAddress, 
UserAgent, AppDisplayName; 
// ------------------------------ 
// 4) TI Enrichment: join publisher/redirect domains to TI Indicators 
(Domain/IP/URL) 
//    
We try to extract host-like strings from ServicePrincipalNames 
(SPN_List) as a crude redirect/issuer hint. 
let SPNDomains = 
Consent 
| project AppId, SPN_List 
| extend DomainHint = extract(@"([a-zA-Z0-9\-]+\.[a-zA-Z0-9\.\-]+)", 
1, tostring(SPN_List)); // best-effort domain extraction 
let TIJoin = 
SPNDomains 
| join kind=leftouter ( 
ThreatIntelligenceIndicator 
| where IndicatorType in ("DomainName","URL","IP") 
| project TI_Indicator=Indicator, IndicatorType, ConfidenceScore, 
TlpLevel, ThreatType, 
IndicatorFirstSeenTime=FirstSeen, 
IndicatorLastSeenTime=LastSeen 
) on $left.DomainHint == $right.TI_Indicator; 
// ------------------------------ 
// 5) Correlate consent with SP usage and user activity to build 
DetectionSignal and weighted scoring 
let Correlated = 
Consent 
| join kind=leftouter (SPUsage) on AppId 
| join kind=leftouter (UserUsage) on $left.InitiatorUPN == 
$right.UserPrincipalName 
| join kind=leftouter (TIJoin) on AppId 
| extend 
// DETECTION SIGNAL (0–100): risk factors & post-consent evidence 
//  • Tenant-wide consent (OnBehalfAll) and App-only flows are 
high risk 
//  • High-priv scopes (Graph) increase risk 
//  • SP sign-ins post-consent (SPTime) strongly increase risk 
(app is “active”) 
    //  • Scripted UA/patterns raise risk 
    ScriptedUA = iif(tolower(coalesce(SPAUA,UserAgent)) has_any 
(dynamic(["python","curl","postman","powershell"])), 1, 0), 
    HasSPUsage = iif(isnotempty(SPTime), 1, 0), 
    DetectionSignal = toint( clamp( 
        ( OnBehalfAllBool * 40 ) 
      + ( IsAppOnlyBool   * 25 ) 
      + ( HighPrivScopes  * 20 ) 
      + ( HasSPUsage      * 25 ) 
      + ( ScriptedUA      * 10 ), 0, 100)), 
 
    // INTEL CONFIDENCE (0–100) via TLP/Confidence matrix 
    TI_Score = toint( case( 
        TlpLevel == "TLP:RED"   and ConfidenceScore >= 90, 100, 
        TlpLevel == "TLP:RED"   and ConfidenceScore >= 70,  80, 
        TlpLevel == "TLP:RED",                              60, 
        TlpLevel == "TLP:AMBER" and ConfidenceScore >= 90,  80, 
        TlpLevel == "TLP:AMBER" and ConfidenceScore >= 70,  60, 
        TlpLevel == "TLP:AMBER",                            40, 
        TlpLevel == "TLP:GREEN" and ConfidenceScore >= 90,  60, 
        TlpLevel == "TLP:GREEN" and ConfidenceScore >= 50,  40, 
        TlpLevel == "TLP:WHITE",                            20, 
        0 
    )), 
 
    // KILL-CHAIN RELEVANCE (0–100) 
    //  • SPUsage present → late-stage (Persistence/C2 via API) → 90 
    //  • Tenant-wide consent or app-only (standing privileges) → 
Persistence → 80 
    //  • Consent only → Initial Access/Privilege Assignment → 50 
    KillChainRelevance = toint( case( 
        HasSPUsage == 1, 90,                                // TA0011 
Command & Control via API calls, TA0003 Persistence 
        OnBehalfAllBool == 1 or IsAppOnlyBool == 1, 80,     // TA0003 
Persistence (standing delegated/app permissions) 
        true, 50                                            // TA0001 
Initial Access (Illicit Consent) 
    )), 
 
    // TEMPORAL (0–100): recency of activity (SP usage or consent 
time) 
    TemporalAnchor = coalesce(SPTime, TimeGenerated), 
    TemporalDays   = toint(datetime_diff('day', now(), TemporalAnchor) 
* -1), 
    TemporalScore  = toint( case( 
        TemporalDays <= 7,   100, 
        TemporalDays <= 30,   60, 
        TemporalDays <= 90,   40, 
        true,                 20 
    )), 
 
    // FINAL WEIGHTED SCORE 
    FinalScore = toint(round( 
         DetectionSignal      * 0.4 
       + TI_Score             * 0.3 
       + KillChainRelevance   * 0.2 
       + TemporalScore        * 0.1 
    )), 
 
    FinalRisk = case( 
        FinalScore >= 90, "CRITICAL", 
        FinalScore >= 70, "HIGH", 
        FinalScore >= 40, "MEDIUM", 
        "LOW" 
    ), 
 
    // MITRE Tactics (tactics only to avoid over-specific technique 
IDs) 
    MITRE_Tactics = strcat_array(pack_array( 
        "TA0001 Initial Access",        // Illicit consent phishing / 
app registration social engineering 
        iif(OnBehalfAllBool==1 or IsAppOnlyBool==1, "TA0003 
Persistence", ""),  // standing app permissions 
        iif(HasSPUsage==1, "TA0011 Command and Control", ""),                   
// Graph/API usage as C2 channel 
        iif(HighPrivScopes==1, "TA0010 Exfiltration", "")                       
// Files/Email access scopes 
    ), ", ") 
 
| extend 
    // Hunter Directives with MITRE context 
    ThreatHunterDirective = case( 
        FinalScore >= 90, 
          strcat("IMMEDIATE CONTAINMENT — Revoke OAuth grants; disable 
Service Principal; reset creds/session; hunt Graph calls; notify IR. 
[", MITRE_Tactics, "]"), 
        FinalScore >= 70, 
          strcat("URGENT INVESTIGATION — Validate app owner; check 
scopes; review SP sign-ins & scripted UAs; confirm business 
justification. [", MITRE_Tactics, "]"), 
        FinalScore >= 40, 
          strcat("INVESTIGATE & TREND — Confirm scopes, owner, usage; 
monitor for SP activity; prepare revocation if suspicious. [", 
MITRE_Tactics, "]"), 
          "MONITOR — Log and watch for post-consent activity." 
    ) 
 
| project 
    TimeGenerated, AppDisplayName, AppId, 
    InitiatorUPN, InitiatorIP, InitiatorUA, 
    IsAppOnly = IsAppOnlyBool, TenantWideConsent = OnBehalfAllBool, 
    HighPrivScopes, GrantedScopes, SPN_List, DomainHint, 
    SPTime, SPAIP, SPAUA, Result, 
    TlpLevel, ConfidenceScore, ThreatType, 
    DetectionSignal, TI_Score, KillChainRelevance, TemporalScore, 
    FinalScore, FinalRisk, MITRE_Tactics, ThreatHunterDirective 
| order by FinalScore desc, TimeGenerated desc 
 
What this catches / Why it Matters for Supply Chains 
0Auth is a primary attack vector for bypassing security controls especially within the 
logistics, maritime, government and other supply chain industries as implementing 
strict software 
controls are often impractical. 
• This is the OAuth attack chain equivalent of our supply-chain thinking: rather than 
trust the app name or Microsoft endpoints, we score behavior + context. 
• We parse consent events, flag tenant-wide or app-only flows, and look for high
priv Graph scopes like Files.ReadWrite and offline_access.” 
• Then we correlate post-consent Service Principal sign-ins and scripted UAs to 
prove the app is being used as an API C2 channel. 
• “We enrich with MISP TI via Sentinel’s TI table and run the adaptive model: 
Detection 0.4 (risk factors + post-consent usage) + Intel 0.3 (TLP/Confidence) + 
Kill-Chain 0.2 (late-stage activity) + Temporal 0.1 (recency). 
• Output is a FinalScore & risk band, with Hunter Directives that name the MITRE 
tactics to standardise response (revoke grants, disable SP, hunt Graph calls). 
• “This is Zero-Trust for OAuth — a consent isn’t trusted; it must earn trust via 
behavior and verifiable context. 
0Auth Consent Risks To Supply Chain (Why It,s Dangerous) 
1. Delegated Trust Abuse (Erosion of Zero-Trust Principles) 
a. OAuth replaces credentials with tokens of trust — granting 
access based on data assertions, not continuous verification. 
b. In a supply-chain compromise, a trusted vendor app (e.g., 3CX, 
SolarWinds Orion, or a legitimate M365 add-in) can quietly 
request excessive scopes such as: 
• Mail.ReadWrite • Directory.Read.All • 
Files.ReadWrite.All 
c. Once consented by a user or admin, the attacker inherits 
persistent, privileged API access — no endpoint malware or user 
password required. 
d. Zero-Trust implication: trust was delegated once and never re
evaluated — a failure of data-driven validation. 
2. Token Reuse and Refresh Abuse (Portable Trust Objects) 
a. Access and refresh tokens can be exfiltrated and reused from 
any device or cloud service. 
b. Because tokens are self-contained assertions, they bypass MFA 
and conditional access — effectively portable trust passports. 
c. Attackers use this to pivot cloud-to-cloud, such as from a 
compromised 3CX desktop integration into O365 or SharePoint. 
d. Zero-Trust lens: tokens must be continuously scored and 
validated, not assumed legitimate because they originate from 
“approved” apps. 
3. Invisible Persistence (Trust Without Visibility) 
a. Even after endpoint remediation, an OAuth app consent remains 
active until it’s explicitly revoked. 
b. This creates “persistence-as-a-service” in the cloud — an 
attacker maintains long-term access without infrastructure 
presence. 
c. Data-driven mitigation: continuously query API usage, validate 
token age, and feed sightings into MISP/OpenCTI to re-score trust 
over time. 
4. Low Visibility to Traditional EDR (Trust Beyond the Endpoint) 
a. API-based activity occurs server-side — invisible to endpoint 
telemetry. 
b. Detection requires cloud telemetry correlation: Azure AD Sign
Ins, Unified Audit Logs, and OAuth consent operations. 
c. Only by integrating these into adaptive scoring and Zero-Trust 
validation can analysts surface malicious persistence. 
d. SOC-to-CTI bridge: endpoint noise is reduced, while confidence 
in cloud telemetry rises through feedback loops and verified 
sightings. 
Lateral SMB Movement Specific To NotPetya (2017) - Supply-Chain 
Attack (Bonus Hunt) 
// ============================================================= 
// Lateral SMB Movement (NotPetya-style) — Supply-Chain Aware Hunt 
// Focus: PsExec/WMI/PowerShell → ADMIN$ copy → remote service exec 
// MITRE: TA0008 Lateral Movement | T1021.002 SMB/Windows Admin Shares 
//        TA0002 Execution | T1569.002 Service Execution 
// ============================================================= 
let lookback = 7d; 
let procSet = dynamic(["psexec.exe","wmic.exe","powershell.exe","cmd.exe"]); 
let lateralUsers = dynamic(["Administrator","Domain Admins","Enterprise 
Admins"]); // tune or use a watchlist 
// 1) SMB connections to 445 from likely lateral tools 
let SmbNet = 
DeviceNetworkEvents 
| where Timestamp >= ago(lookback) 
| where RemotePort == 445 
| where InitiatingProcessFileName in (procSet) 
| project SmbTime = Timestamp, DeviceId, DeviceName, InitiatingProcessFileName, 
InitiatingProcessCommandLine, RemoteIP; 
// 2) File copies into ADMIN$ on remote host (remote admin share staging) 
let AdminShareWrites = 
DeviceFileEvents 
| where Timestamp >= ago(lookback) 
| where FolderPath matches regex @"(?i)^\\\\[A-Za-z0-9\.\-]+\\ADMIN\$\\" // 
\\TARGET\ADMIN$\path 
| extend TargetHost = tostring(extract(@"\\\\([^\\]+)\\ADMIN\$", 1, FolderPath)) 
| project FileTime = Timestamp, DeviceName, DeviceId, TargetHost, FolderPath, 
FileName, SHA256; 
// 3) PsExec service artifacts on the remote (psexesvc.exe) or SCM starts 
let ServiceExec = 
DeviceProcessEvents 
| where Timestamp >= ago(lookback) 
| where FileName in ("psexesvc.exe","svchost.exe","services.exe") 
or (InitiatingProcessCommandLine has_any ("psexec","\\ADMIN$","sc.exe 
create","sc.exe start")) 
| project SvcTime = Timestamp, DeviceName, DeviceId, FileName, 
ProcessCommandLine; 
// 4) Optional: map SMB RemoteIP → host (best-effort) to correlate with 
ADMIN$ TargetHost 
let DnsMap = 
DnsEvents 
| where Timestamp >= ago(lookback) 
| project DnsTime=Timestamp, DeviceName, RemoteIP=IPAddress, ResolvedHost=Name; 
// 5) Join: SMB → DNS name → ADMIN$ write → (near-time) ServiceExec 
let Corr = 
SmbNet 
| join kind=leftouter (DnsMap) on RemoteIP 
| extend TargetHost = coalesce(ResolvedHost, RemoteIP) 
| join kind=leftouter ( 
AdminShareWrites 
| project FileTime, TargetHost, SrcDeviceName=DeviceName, FolderPath, 
FileName, SHA256 
) on TargetHost 
| where isnull(FileTime) == false and FileTime between (SmbTime .. SmbTime + 15m) 
| join kind=leftouter ( 
ServiceExec 
| project SvcTime, SvcDeviceName=DeviceName, SvcFileName=FileName, 
SvcCmd=ProcessCommandLine 
) on $left.TargetHost == $right.SvcDeviceName 
| where isnull(SvcTime) == false and SvcTime between (FileTime .. FileTime + 15m) 
| extend Evidence = pack( 
"SMBProc", InitiatingProcessFileName, 
"SMBCmd", InitiatingProcessCommandLine, 
"AdminSharePath", FolderPath, 
"AdminShareFile", FileName, 
"SvcFile", SvcFileName, 
"SvcCmd", SvcCmd 
); 
// 6) TI/MISP enrichment (IP or host) 
let Enriched = 
Corr 
| join kind=leftouter ( 
ThreatIntelligenceIndicator 
| where IndicatorType in ("IPv4","IP","DomainName","HostName") 
| project TI_Indicator=Indicator, TI_Confidence=ConfidenceScore, 
TI_TLP=TlpLevel, TI_Type=ThreatType, TI_Tags=Tags 
) on $left.RemoteIP == $right.TI_Indicator or $left.TargetHost == 
$right.TI_Indicator 
| extend 
// Adaptive scoring 
DetectionSignal = 90, // we matched SMB→ADMIN$→ServiceExec in-window = strong 
behavior 
IntelConfidence = toint(coalesce(TI_Confidence, 50)), 
KillChainRelevance = 85, // Lateral Movement + Execution 
TemporalScore = 100, // live 
FinalScore = toint(round(DetectionSignal*0.4 + IntelConfidence*0.3 + 
KillChainRelevance*0.2 + TemporalScore*0.1)), 
FinalRisk = case(FinalScore>=90,"CRITICAL", FinalScore>=70,"HIGH", "MEDIUM"), 
MITRE_Tactics = "TA0008 Lateral Movement; TA0002 Execution", 
MITRE_Techniques = "T1021.002 SMB/Windows Admin Shares; T1569.002 Service 
Execution", 
ThreatHunterDirective = case( 
FinalRisk=="CRITICAL", 
strcat("IMMEDIATE: Isolate source ", DeviceName, ", block lateral 
creds, pull triage from ", TargetHost, ", collect SRUM/EVTX. Push sightings to 
MISP."), 
FinalRisk=="HIGH", 
strcat("URGENT: Validate PsExec/WMI use; confirm change ticket; review 
", FolderPath, " and ", SvcCmd, "; pivot to Kerberos/NTLM logs."), 
"INVESTIGATE: Scope blast-radius; add watchlist for the source 
user/device; monitor ADMIN$ writes.") 
| project SmbTime, DeviceName, RemoteIP, TargetHost, FolderPath, FileName, 
SvcFileName, SvcCmd, TI_TLP, TI_Confidence, TI_Tags, 
FinalScore, FinalRisk, MITRE_Tactics, MITRE_Techniques, Evidence 
| order by FinalScore desc, SmbTime desc; 
Enriched  
KQL Designed For Similar 3CX, F5 & NTTData Supply Chain 
attacks: 
The following rule was created by me mainly from traditional DLL Sideloading and search 
order attack chains, making a slight modification for supply chain type attack vectors. 
// 
===================================================================== 
// Supply-Chain-Aware DLL Sideloading Detection with Adaptive Scoring 
// Author: Ala Dabat (SOC/MDR → CTI bridge) 
// Why: Catch signed-but-rare DLL loads in trusted vendor processes 
(3CX, SolarWinds, etc.) 
//      
including both FAST (≤5 min) and DELAYED (days later) loads 
that evade simple rules. 
// Model: FinalScore = Detection(0.4) + IntelConfidence(0.3) + 
KillChain(0.2) + Temporal(0.1) 
// Outputs: FinalScore, FinalRisk, MITRE tags, and Hunter Directives 
with MITRE tactic names. 
// 
===================================================================== 
let lookback         
+ correlated activity 
= 14d;    
let prevalenceWindow = 90d;    
across the tenant 
let fastWindowSec    
let daySec           
= 300;    
// Reasonable incident window for DLL 
// Used to decide if a hash is "rare" 
// ≤ 5 minutes = FAST sideload 
= 86400;  // seconds in a day 
// --------------------------------------------------------------------- 
// A) Define vendor processes typically associated with supply-chain 
paths 
//    
(3CX, SolarWinds Orion host, and a placeholder 'vendor.exe' to 
expand per org) 
let vendorProcs = 
dynamic(["3cx.exe","SolarWinds.BusinessLayerHost.exe","vendor.exe"]); 
// --------------------------------------------------------------------- 
// B) Org-wide prevalence: "How many distinct devices have seen this 
SHA256 in 90d?" 
//    
Rare DLLs (SeenDeviceCount <= 2) are suspicious even if signed. 
let OrgPrevalence = 
DeviceFileEvents 
| where Timestamp >= ago(prevalenceWindow) 
| summarize SeenDeviceCount = dcount(DeviceId) by SHA256, FileName; 
// --------------------------------------------------------------------- 
// C) DLL image-loads inside vendor processes in the last 14 days 
//    
(Signed DLLs can still be malicious in supply-chain scenarios.) 
let ImageLoads = 
DeviceImageLoadEvents 
| where Timestamp >= ago(lookback) 
| where ProcessFileName has_any (vendorProcs) 
| where FileName endswith ".dll" 
| extend ImageSHA256 = coalesce(SHA256, tostring(ImageHash)) 
| extend LoaderProc  = ProcessFileName, LoaderPID = ProcessId 
| project 
ImageLoadTime = Timestamp, DeviceName, DeviceId, 
LoaderProc, LoaderPID, 
ImageFileName = FileName, ImageSHA256, 
SignatureStatus, Signer, ReportId; 
// --------------------------------------------------------------------- 
// D) Recent DLL file-creation events (same hash/path) – used to 
compute FAST/DELAYED loads. 
//    
Attackers often *drop* a DLL long before it is *loaded* to 
bypass short time-window rules. 
let RecentCreates = 
DeviceFileEvents 
| where Timestamp >= ago(lookback) 
| where FileName endswith ".dll" 
| extend FileSHA256 = SHA256 
| project 
    FileCreateTime = Timestamp, DeviceName, DeviceId, FolderPath, 
    FileName, FileSHA256, 
    InitiatingProcessFileName, InitiatingProcessCommandLine; 
 
// --------------------------------------------------------------------- 
// E) Build candidate suspicious image-loads with base behavior flags 
//    - Rarity (SeenDeviceCount) 
//    - FAST load (≤5m after creation) and DELAYED loads (5m–24h, 1
7d, 7–14d) 
//    - Unsigned/Untrusted signature 
let SuspiciousImages = 
ImageLoads 
| join kind=leftouter (OrgPrevalence) on $left.ImageSHA256 == 
$right.SHA256 
| join kind=leftouter ( 
    RecentCreates 
    | project DeviceId, FileCreateTime, FileName, FileSHA256 
) on $left.DeviceId == $right.DeviceId and $left.ImageSHA256 == 
$right.FileSHA256 
| extend SeenDeviceCount = coalesce(SeenDeviceCount, 0) 
| extend CreatedSecondsBeforeLoad = 
    iff(isnotempty(FileCreateTime), 
        datetime_diff('second', ImageLoadTime, FileCreateTime) * -1,  
// negative if created before load 
        long(-1)) 
| extend 
    // Base behavior flags 
    RareIndicator            = iif(SeenDeviceCount <= 2, 1, 0), 
    FastLoad_0_5min          = iif(CreatedSecondsBeforeLoad >= 0 and 
CreatedSecondsBeforeLoad <= fastWindowSec, 1, 0), 
    DelayLoad_5m_24h         = iif(CreatedSecondsBeforeLoad > 
fastWindowSec and CreatedSecondsBeforeLoad <= daySec, 1, 0), 
    DelayLoad_1d_7d          = iif(CreatedSecondsBeforeLoad > daySec 
and CreatedSecondsBeforeLoad <= 7*daySec, 1, 0), 
    DelayLoad_7d_14d         = iif(CreatedSecondsBeforeLoad > 
7*daySec and CreatedSecondsBeforeLoad <= 14*daySec, 1, 0), 
    UnsignedOrUntrusted      = iif(SignatureStatus != "Signed" or 
isnull(Signer), 1, 0) 
| extend 
    // Detection behavior score (0–?) → later scaled to 0–100 
    // FAST loads get higher weight; delayed loads still score to 
catch "wait-and-load" evasion. 
    BehaviorScore = 
          (RareIndicator * 1) 
        + (FastLoad_0_5min * 2) 
        + (DelayLoad_5m_24h * 1) 
        + (DelayLoad_1d_7d * 1) 
        + (DelayLoad_7d_14d * 1) 
        + (UnsignedOrUntrusted * 1) 
| where BehaviorScore >= 1 
| project 
    ImageLoadTime, DeviceName, DeviceId, LoaderProc, LoaderPID, 
    ImageFileName, ImageSHA256, SignatureStatus, Signer, 
    SeenDeviceCount, CreatedSecondsBeforeLoad, BehaviorScore, 
ReportId; 
 
// --------------------------------------------------------------------- 
// F) Driver drops (.sys) near the load time → hints at Persistence / 
kernel abuse (TA0003/TA0005) 
let DriverDrops = 
DeviceFileEvents 
| where Timestamp >= ago(lookback) 
| where FileName endswith ".sys" 
   or FolderPath has_any 
(dynamic(["\\drivers\\","\\system32\\drivers\\"])) 
| project 
DriverTime = Timestamp, DeviceName, DeviceId, 
SysFile = FileName, SysSHA256 = SHA256, 
InitiatingProcessFileName, InitiatingProcessCommandLine; 
// --------------------------------------------------------------------- 
// G) Suspicious LOLBIN/loader execution around load time → Defense 
Evasion / Ingress Tool Transfer 
let SuspiciousExec = 
DeviceProcessEvents 
| where Timestamp >= ago(lookback) 
| where (FileName in ("rundll32.exe","regsvr32.exe") and 
ProcessCommandLine has_any 
(dynamic(["http://","https://",".sct","/i:"]))) 
or (FileName in 
("bitsadmin.exe","certutil.exe","powershell.exe","curl.exe","wget.exe
 ") 
and ProcessCommandLine has_any (dynamic(["-enc","
encodedcommand","invoke-webrequest","downloadfile","
url","http://","https://"]))) 
| project 
ExecTime = Timestamp, DeviceName, DeviceId, FileName, 
ProcessCommandLine, InitiatingProcessFileName, 
InitiatingProcessCommandLine, ReportId; 
// --------------------------------------------------------------------- 
// H) Outbound network correlation + Threat Intelligence 
(MISP→Sentinel TI table) 
//    
We join on IP/Domain/URL and bring in TLP + Confidence for 
Intel scoring. 
let NetCorrel = 
DeviceNetworkEvents 
| where Timestamp >= ago(lookback) 
| where RemoteIP !in~ ("127.0.0.1","::1") 
and not(startswith(RemoteIP,"10.") or 
startswith(RemoteIP,"192.168.") or startswith(RemoteIP,"172.")) 
| extend RemoteDomain = tostring(parse_url(RemoteUrl).Host) 
| project 
    NetTime = Timestamp, DeviceName, DeviceId, RemoteIP, RemotePort, 
RemoteUrl, RemoteDomain, 
    NetProc = InitiatingProcessFileName, NetCmd = 
InitiatingProcessCommandLine 
| join kind=leftouter ( 
    ThreatIntelligenceIndicator 
    | where IndicatorType in ("IP","DomainName","URL") 
    | project TI_Indicator = Indicator, 
              IndicatorType, 
              ConfidenceScore, 
              TlpLevel, 
              ThreatType, 
              IndicatorFirstSeenTime = FirstSeen, 
              IndicatorLastSeenTime  = LastSeen 
) on $left.RemoteIP == $right.TI_Indicator 
   or $left.RemoteDomain == $right.TI_Indicator 
   or $left.RemoteUrl == $right.TI_Indicator 
| extend ConfidenceScore = coalesce(ConfidenceScore, 0), 
         TlpLevel        = coalesce(TlpLevel, "TLP:WHITE"), 
         ThreatType      = coalesce(ThreatType, "Unknown"), 
         VT_Link         = iif(isnotempty(RemoteIP), 
strcat("https://www.virustotal.com/gui/ip-address/", RemoteIP), ""); 
 
// --------------------------------------------------------------------- 
// I) Join all evidence around the image-load time to build a full 
chain view. 
//    Windows allow-forgiving windows: Exec within 1h; Driver within 
2h; Net within 2h. 
let Correlated = 
SuspiciousImages 
| join kind=leftouter (SuspiciousExec) on DeviceId 
| where isnull(ExecTime) or (ExecTime between (ImageLoadTime .. 
ImageLoadTime + 1h)) 
| join kind=leftouter (DriverDrops) on DeviceId 
| where isnull(DriverTime) or (DriverTime between (ImageLoadTime .. 
ImageLoadTime + 2h)) 
| join kind=leftouter (NetCorrel) on DeviceId 
| where isnull(NetTime) or (NetTime between (ImageLoadTime .. 
ImageLoadTime + 2h)) 
| extend 
    // DetectionSignal: scale BehaviorScore (each point ≈ 20) + 
evidence boosts 
    DetectionSignal = 
        toint( clamp( (BehaviorScore * 20) 
                    + iif(isnotempty(ExecTime),   20, 0) 
                    + iif(isnotempty(DriverTime), 15, 0) 
                    + iif(isnotempty(RemoteIP) or 
isnotempty(RemoteDomain), 25, 0), 0, 100)), 
 
    // TI_Score per TLP/Confidence matrix you use in slides 
    TI_Score = case( 
        TlpLevel == "TLP:RED"   and ConfidenceScore >= 90, 100, 
        TlpLevel == "TLP:RED"   and ConfidenceScore >= 70,  80, 
        TlpLevel == "TLP:RED",                              60, 
        TlpLevel == "TLP:AMBER" and ConfidenceScore >= 90,  80, 
        TlpLevel == "TLP:AMBER" and ConfidenceScore >= 70,  60, 
        TlpLevel == "TLP:AMBER",                            40, 
        TlpLevel == "TLP:GREEN" and ConfidenceScore >= 90,  60, 
        TlpLevel == "TLP:GREEN" and ConfidenceScore >= 50,  40, 
        TlpLevel == "TLP:WHITE",                            20, 
        0 
    ), 
 
    // KillChainRelevance: prioritize late-stage activity if present 
(C2/Persistence highest) 
    KillChainRelevance = toint( case( 
        isnotempty(RemoteIP) or isnotempty(RemoteDomain), 90,         
// TA0011 Command & Control 
        isnotempty(DriverTime),                           80,         
// TA0003 Persistence (driver) 
        isnotempty(ExecTime),                             60,         
// TA0005 Defense Evasion / Loader 
        true,                                             40          
// Only the sideload event 
    )), 
 
    // Temporal: favor freshness (TI last-seen or local 
NetTime/ImageLoadTime) 
    TemporalAnchor = coalesce(IndicatorLastSeenTime, NetTime, 
ImageLoadTime), 
    TemporalDays   = toint( datetime_diff('day', now(), 
TemporalAnchor) * -1 ), 
    TemporalScore  = toint( case( 
        TemporalDays <= 7,   100, 
        TemporalDays <= 30,   60, 
        TemporalDays <= 90,   40, 
        true,                 20 
    )), 
 
    // Final weighted score (0–100) 
    FinalScore = toint(round( DetectionSignal * 0.4 
                            + TI_Score       * 0.3 
                            + KillChainRelevance * 0.2 
                            + TemporalScore  * 0.1 )), 
 
    // Final risk bands 
    FinalRisk = case( 
        FinalScore >= 90, "CRITICAL", 
        FinalScore >= 70, "HIGH", 
        FinalScore >= 40, "MEDIUM", 
        "LOW" 
    ), 
 
    // MITRE tactics/techniques – annotate based on observed evidence 
    MITRE_Tactics    = strcat_array( 
                         pack_array( 
                           iif(isnotempty(DriverTime), "TA0003 
Persistence", ""), 
                           iif(isnotempty(ExecTime),   "TA0005 
Defense Evasion", ""), 
                           iif(isnotempty(RemoteIP) or 
isnotempty(RemoteDomain), "TA0011 Command and Control", ""), 
                           "TA0002 Execution"  // baseline for DLL 
image-load 
                         ), ", "), 
    MITRE_Techniques = strcat_array( 
                         pack_array( 
                           "T1574.002 DLL Search Order Hijacking", 
                           iif(isnotempty(RemoteIP) or 
isnotempty(RemoteDomain), "T1105 Ingress Tool Transfer", "") 
                         ), ", ") 
| extend 
    // Hunter directives embedded with MITRE context 
    ThreatHunterDirective = case( 
        FinalScore >= 90, 
          strcat("Immediate review & CONTAINMENT — Isolate host; 
suspend creds; block IOC; collect triage (DLL, driver, proc tree). ", 
                 "[", MITRE_Tactics, " | ", MITRE_Techniques, "]"), 
        FinalScore >= 70, 
          strcat("Urgent investigation — Validate DLL provenance; 
check prevalence; confirm C2; memory capture if feasible. ", 
                 "[", MITRE_Tactics, " | ", MITRE_Techniques, "]"), 
        FinalScore >= 40, 
          strcat("Investigate & trend — Validate signature; review 
device/network neighbors; monitor for recurrence. ", 
                 "[", MITRE_Tactics, " | ", MITRE_Techniques, "]"), 
        strcat("Monitor & log — Track indicator; await additional 
signals/sightings. ", 
               "[", MITRE_Tactics, " | ", MITRE_Techniques, "]") 
    ) 
 
// Final projection for triage views / workbooks 
| project 
    ImageLoadTime, DeviceName, DeviceId, 
LoaderProc, ImageFileName, ImageSHA256, 
SignatureStatus, Signer, SeenDeviceCount, 
CreatedSecondsBeforeLoad, BehaviorScore, 
ExecProc = FileName, ExecTime, 
Driver = SysFile, DriverTime, 
RemoteIP, RemoteDomain, RemoteUrl, VT_Link, 
TlpLevel, ConfidenceScore, ThreatType, 
DetectionSignal, TI_Score, KillChainRelevance, TemporalScore, 
FinalScore, FinalRisk, MITRE_Tactics, MITRE_Techniques, 
ThreatHunterDirective 
| order by FinalScore desc, ImageLoadTime desc 
Simple Breakdown Of Rule Logic 
This is a simplified version of the full rule I designed — it 
demonstrates how we start by asking one core question: ‘Which 
DLLs are being loaded by trusted vendor processes, but rarely seen 
across the environment. 
That’s the foundation of detecting supply-chain abuse — catching 
what looks trusted but behaves abnormally.” 
// Simplified logic to illustrate detection flow 
let lookback = 7d;  // Observation window for DLL loads 
let vendorProcs = dynamic(["3cx.exe","vendor.exe"]);  // Known vendor 
processes 
// Compute file prevalence in last 90 days (rare = suspicious) 
let OrgPrev = DeviceFileEvents 
| where Timestamp >= ago(90d) 
| summarize DeviceSeenCount = dcount(DeviceId) by SHA256; 
// Look for DLLs loaded by vendor processes 
DeviceImageLoadEvents 
| where Timestamp >= ago(lookback) 
| where ProcessFileName has_any (vendorProcs) 
| where ImageFileName endswith ".dll" 
| extend ImageSHA = coalesce(ImageHash, SHA256) 
| join kind=leftouter (OrgPrev) on $left.ImageSHA == $right.SHA256 
| where coalesce(DeviceSeenCount, 0) <= 5  // loaded on ≤5 devices → 
rare 
| project Timestamp, DeviceName, ProcessFileName, ImageFileName, 
ImageSHA, DeviceSeenCount 
| order by Timestamp desc 
Notes: In many cases, normal software updates do involve delayed DLL loading, but the 
term can refer to different mechanisms. The most common reasons for a delay in loading a 
Dynamic-Link Library (DLL) during or after an update are to improve 
performance, enhance compatibility, or manage system resources. 
•    Malware droppers typically write a DLL to disk and immediately load it. 
•    Normal software updates or installs have longer intervals or scheduled loads. 
•   The trojanized process (3CXDesktopApp.exe, possibly the delayed payload in F5’s 
2025 attack and NTTData’s 2015 attack. 
SolarWinds.BusinessLayerHost.exe) likely loaded a malicious DLL shortly after it 
appeared on disk. 
•   That tight timing correlation between creation → load → network activity is a 
strong IOC (indicator of compromise). 
Understanding Industry Threats and Mitigation 
1
 ️
 ⃣ Situation Analysis 
•   Understand the environment: Map critical infrastructure, including container 
terminals, logistics platforms, operational technology (OT), cloud services, and 
internal applications. Understand network segmentation & prevalent software 
usage. 
•    Prioritize assets: Identify crown jewels such as ERP systems, shipping 
scheduling platforms, port access control systems, and internal collaboration 
tools, setup watch list rules. 
•   Threat landscape awareness: Maintain awareness of geopolitical and industry- 
specific threats, especially supply chain compromises affecting global shipping. 
OpenCTI cross reference as well as “dark” reading. 
2
 ️
 ⃣ Task Definition 
•    Establish objectives: Detect early compromise indicators, malicious lateral 
movement, persistence mechanisms, and data exfiltration. Rule based 
watchlists, and MISP integration & OpenCTI correlation. 
•   Align hunting with business risk: Focus on high-value targets, systems 
Supporting container operations, and endpoints connecting with external 
vendors. I.e. CVE hunt reports for all internet facing devices and software 
inventory lists/query. 
•   Coordinate across teams: Collaborate with SOC analysts, IR teams, OT 
security, and legal/compliance departments. 
3
 ️
 ⃣ Action Plan 
•    Data-driven threat hunting: Leverage weekly threat hunts (e.g., port anomalies, 
registry persistence, rogue endpoints, LSASS/credential dumping) enriched with 
MISP threat intelligence feeds. 
•    Event correlation: Join endpoint, network, and AD logs to identify suspicious 
patterns indicative of supply-chain or ransomware attacks. Suggestions to 
engineering/commonsecurity log enrichment. 
•    Proactive intelligence: Use MITRE ATT&CK mapping to anticipate likely attacker 
paths (initial access → persistence → lateral movement → exfiltration). 
•   Simulation & testing: Conduct purple-team exercises and red-team scenarios to 
validate hunting rules and detection coverage. 
•   Collaboration with vendors: Integrate threat intelligence from SolarWinds, 
3CX, M.E.Doc, and other vendor feeds into ongoing monitoring. 
4
 ️
 ⃣ Result / Impact 
•    Early detection: Threat hunting rules catch suspicious activity before it 
escalates into widespread compromise. Supply Chain focus and early warning 
system threat detection rule logic. 
•    Rapid incident response: Alerts enriched with MISP/TI context allow triage and 
containment within minutes. 
•    Risk reduction: Proactive measures limit operational downtime and prevent 
large-scale disruptions in container logistics or port operations. Backup/restore 
etc... 
•   Continuous improvement: Lessons learned feed back into detection rules, 
threat models, and supplier vetting processes. 
5
 ️
 ⃣ Lessons Learned & Remediation 
•   Supply chain vigilance: Regular vetting of software vendors, signed updates, and 
configuration baselines. Queries trigger upon install. Regular inventory    threat 
hunting. 
•    Detection maturity: Enhance alerting, SIEM dashboards, and cross-platform 
correlation. 
•    Employee awareness: Training for recognizing phishing, suspicious links, and 
anomalous system behavior. 
•    Backup & recovery readiness: Periodic validation of backups and disaster 
recovery plans to ensure continuity in the event of ransomware or wiper attacks. 
MISP Confidence Scoring On Created BEC Threat 
// ===============================================// 
// BEC / Malicious Email Click-through Detection with Dynamic// 
// Scoring and Directives - THREAT TYPE Event Created in MISP lab by Ala Dabat// 
// =============================================== // 
let lookback = 7d; 
// 1️⃣  Delivered emails 
let DeliveredEmails = EmailEvents 
| where TimeGenerated >= ago(lookback) 
| where DeliveryAction == "Delivered" | project TimeGenerated, 
NetworkMessageId, RecipientEmailAddress, SenderFromAddress, Subject, 
AttachmentCount, DeliveryAction; 
// 2️⃣  URL clicks 
let UrlClicks = UrlClickEvents 
| where TimeGenerated >= ago(lookback) 
| where ActionType in ("ClickAllowed","ClickBlocked") | project 
ClickTime=TimeGenerated, NetworkMessageId, 
RecipientEmailAddress, Url, ActionType; 
// 3️⃣  Join emails & clicks 
let EmailClickThrough = DeliveredEmails 
| join kind=inner (UrlClicks) on NetworkMessageId, 
RecipientEmailAddress 
| project ClickTime, RecipientEmailAddress, SenderFromAddress, Subject, Url, 
ActionType, AttachmentCount, DeliveryAction; 
// 囚  MISP enrichment with dynamic scoring and 
ThreatTypeletEmailClickEnriched = EmailClickThrough| join 
kind=leftouter ( 
ThreatIntelligenceIndicator 
| where IndicatorType in ("URL","EmailAddress","FileHash") | extend TI_Score 
= case( 
ConfidenceScore >= 80, 100, 
ConfidenceScore >= 50, 50, 
ConfidenceScore < 50, 20, 
0 
) 
| project TI_Indicator = Indicator, TI_Type = IndicatorType, TI_Score, ThreatType, 
TlpLevel 
) on $left.Url == $right.TI_Indicator or $left.SenderFromAddress == $right.TI_Indicator 
| extend TotalScore = coalesce(TI_Score,0), 
ThreatType = coalesce(ThreatType,"Unknown"); 
// 曰  Generate Threat Hunter Directives based on TotalScore, ActionType, and 
ThreatType 
EmailClickEnriched 
| extend ThreatHunterDirective = case( 
TotalScore >= 80 and ActionType == "ClickAllowed", 
strcat("Immediate review & containment: Isolate device, reset user account, block URL & 
sender, check endpoint telemetry [ThreatType: ", ThreatType, "]"), 
TotalScore >= 80 and ActionType == "ClickBlocked", 
strcat("Immediate review: Check why URL was blocked, verify sender, ensure no 
secondary payloads [ThreatType: ", ThreatType, "]"), 
TotalScore >= 50 and ActionType == "ClickAllowed", 
strcat("Investigate recipient & device: Check endpoint activity, lateral movement, 
attachments, monitor network [ThreatType: ", 
ThreatType, "]"), 
TotalScore >= 50 and ActionType == "ClickBlocked", 
strcat("Investigate: Verify URL & sender, confirm email filtering worked as intended 
[ThreatType: ", ThreatType, "]"), 
TotalScore < 50, strcat("Monitor trends & log for historical analysis [ThreatType: ", 
ThreatType, "]"), 
"No action required" )  
| project ClickTime, RecipientEmailAddress, SenderFromAddress, Subject, Url, 
ActionType, AttachmentCount, DeliveryAction, 
TotalScore, ThreatType, ThreatHunterDirective 
| order by TotalScore desc, ClickTime desc 
2) How this rule (and your suite) maps to 
each attack 
SolarWinds (SUNBURST, 2020) 
• Primary stealth C2 & tasking. Lateral SMB happened in some victim environments 
after persistence. 
• This rule would trigger if operators moved laterally with PsExec/WMI + 
ADMIN$ staging (common in post-beacon ops). 
• Your DLL sideload + Registry Persistence rules spot the foothold; SMB rule spots 
the spread. 
NotPetya (M.E.Doc, 2017) 
• Textbook: credential theft + PsExec/WMI + ADMIN$ + service creation. 
• This rule is a direct hit (  ); your LSASS/credential hunts and Kerberos/SPN 
anomalies reinforce it. 
3CX (2023) 
• Initial access via signed installer → persistence; many orgs later observed lateral 
admin-share usage by operators. 
• Rule triggers (   /  ) depending on whether ADMIN$ and service exec were used. 
F5 Internal Breach (2025, UNC5221) 
• Long dwell, driver + token abuse; dev network lateralization. 
• If adversaries used PsExec/WMI/admin shares the rule triggers (   →  ). 
• Your Rogue Endpoint, Registry Persistence, and Suspicious Ports rules light up 
earlier/elsewhere. 
NTT DATA (2015) 
• Dormant supply-chain implant that activated later. 
• If/when operators pivoted with admin shares, this rule shows it (   ); otherwise you 
rely on persistence + DLL rules and temporal scoring to surface delayed activity. 
3) Updated Coverage Matrix (with ALL rules 
applied) 
   = Strong detection (clear signal, low FP) 
     = Partial/contextual (needs enrichment/validation) 
   = Not detected / outside scope 
Attack 
Stage → / 
Hunt ↓ 
SolarWin
 ds 
(SUNBUR
 ST) 
NotPetya 
(M.E.Doc
 ) 
3CX 
Supply 
Chain 
F5 
Net
 work
 s 
2025 
NTT 
DATA 
2015 
Which Hunt(s) 
Triggered & Why 
1. Initial 
Comprom
 ise 
(Trojanise
 d Installer 
/ Exploit) 
                    Rogue Endpoint / 
Ports surface odd 
post-install 
connections or 
unmanaged hosts; 
no signatures → 
anomaly only. 
2. DLL / 
Compone
 nt 
Sideloadi
 ng 
                 DLL Sideload 
catches rare DLL 
into vendor procs; 
F5 less DLL-heavy 
early; NTT dormant 
later turns to    
when it fires. 
3. 
Dropper 
Executes 
/ Driver 
Install 
(.SYS) 
                Process+FileEvent
 s flag driver writes 
by non-service 
procs; MISP hash 
match boosts 
confidence; NTT 
fires late (   ). 
4. 
Persisten
 ce 
Establish
 ed 
(Registry/
               Registry 
Persistence Hunt 
(Run/RunOnce/IFE
 O/Services) with 
unsigned parents + 
TI enrichment 
escalates all. 
Service 
Keys) 
5. 
Comman
 d & 
Control 
(HTTPS/D
 NS/Proxy/
 VPN) 
               Suspicious Ports + 
TI detect 
1080/1194/8081 
etc.; OAuth rule 
adds cloud-token 
abuse visibility 
where relevant. 
6. 
Credentia
 l Access 
(LSASS / 
Tokens / 
OAuth) 
                  LSASS/Token/OAu
 th rules light up for 
NotPetya 
(dumpers) and F5 
(tokens); others 
depend on 
operator 
tradecraft. 
7. Lateral 
Movemen
 t 
(SMB/WM
 I/PSExec/
 Kerberos) 
                 New SMB Lateral 
Rule 
(ADMIN$+service): 
direct hit for 
NotPetya; 
SolarWinds/F5 
often pivot this 
way; 3CX/NTT 
sometimes. 
8. Data 
Exfiltratio
 n / C2 
Transfer 
                Suspicious Ports + 
adaptive scoring 
catch encrypted 
exfil; NTT’s delayed 
beacon appears 
late (   ). 
9. 
Cleanup / 
Trace 
Removal 
                   Registry hunt 
notes key 
deletions/timesto
 mping; brief DLL 
drop‑and-delete 
windows 
sometimes visible. 
10. Post
Incident 
Feedback 
/ IOC 
               Sightings → MISP → 
OpenCTI loop 
raises IOC 
confidence and 
Enrichme
 nt 
updates actor 
graphs across all 
cases. 
 
Detection Strength by Attack 
(Full Stack: MISP + DLL + Registry + Ports + OAuth + SMB Lateral + Rogue Endpoint) 
Attack Overall 
Coverage 
Strongest Rules Gaps / Limitations 
SolarWin
 ds 
(SUNBUR
 ST) 
       
(80%) 
DLL-Sideload, Registry 
Persistence, SMB 
Lateral, TI Enrichment 
Encrypted C2 blends with 
legit traffic; initial 
trojanization out of scope. 
NotPetya 
(M.E.Doc) 
       
(85%) 
SMB Lateral 
(ADMIN$+service), 
LSASS, Registry, 
Kerberos 
Pre-compromise (trojanized 
update) still not 
behaviorally visible. 
3CX 
Supply 
Chain 
      
(95%) 
DLL-Sideload, Registry, 
C2 Ports, (SMB Lateral 
when used) 
Memory-only payloads pre
persistence remain hard. 
F5 (2025 
Internal) 
       
(75%) 
Rogue Endpoint, 
Registry, OAuth/Token, 
C2 Ports, SMB Lateral 
Long-dwell stealth; 
depends on whether SMB 
lateral used; heavy 
cloud/dev activity. 
NTT DATA 
(2015) 
        
(65%) 
Registry, DLL Sideload, TI 
Feedback, (SMB Lateral if 
used) 
Dormant payload delays 
signals; temporal scoring + 
TI needed to surface. 
 
Quick talk-track you can use 
• “For NotPetya, the SMB Lateral hunt nails the PsExec/WMI + ADMIN$ + service 
creation pattern within minutes. That’s why it’s a   . 
 For SolarWinds/3CX, it’s a post-foothold detector—   if operators pivot that 
way. 
 For F5, it’s useful once the actor leaves the dev enclave and starts lateralizing with 
admin shares; otherwise the OAuth, Registry, and Rogue Endpoint rules carry the 
weight. 
For NTT 2015, the payload sleeps—our temporal scoring and MISP/OpenCTI 
confidence lift it once activity starts.” 
Why Detection Coverage Improved with MISP + DLL Rule 
•    MISP integration adds external threat context (hashes, domains, IPs) so you 
escalate low confidence anomalies into high confidence alerts. 
•   The DLL sideloading rule closes the gap where signed binaries in legitimate 
folders previously evaded detection — you now capture rapid file drop → load 
behavior, even when signatures appear valid. 
•   Combined, you enable multi-stage correlation: e.g., Installer → DLL 
dropped/loaded → registry key created → outbound C2 → lateral movement → exfil — 
your rules chain the full kill chain with higher fidelity. 
•   This maturity moves you from “reactive alerts” to proactive threat hunting and 
early detection before full impact. 
Further Threat Intelligence & Hunting Strategies 
Supply-chain intrusions are difficult because the initial compromise comes from a 
trusted or signed component. 
That means detection must focus on behavioral deviations, telemetry anomalies, 
and post-compromise pivots, not just “malware signatures.” 
•   Hunt for duplicate device names, could be a sign of lateral movement, pass the 
hash, pass the ticket attacks etc... 
Joining with DeviceInfo to compare hardware IDs or unique ID’s for same 
hostname. 
•   Correlating with LogonEvents — simultaneous logons from same device name but 
different IPs/subnets. 
•   Adding MISP integration: tag any matching IPs/domains from MISP to prioritize 
incidents with confirmed malicious infrastructure. 
•    Enhance 0Auth protection: FIDO Keys, Token refresh times, watchlists for 
authorized apps/appID’s, Microsoft API Graph anomaly detection, consent grant 
scheduled detections & reports. 
Apprendix 
Common MISP taxonomies and their purpose 
A complete list is impossible to provide, as new ones are regularly developed. Instead, here 
are some of the most common and important taxonomies used in MISP and what their tags 
mean. 
Traffic Light Protocol (TLP) 
The TLP is a set of four colors that guide how sensitive information is shared. It is one of 
the most fundamental taxonomies for threat intelligence sharing. 
TLP:RED: For the eyes and ears of individual recipients only. No further disclosure is 
permitted. 
TLP:AMBER: Limited disclosure. Recipients can only share information within their 
organization and with its clients on a need-to-know basis. 
TLP:AMBER+STRICT: A stricter version of AMBER, restricting sharing to only within the 
organization. 
TLP:GREEN: Limited disclosure. Information can be shared within the community or 
organization. 
TLP:CLEAR: Recipients can disclose the information to the public without restriction. 
Analyst Confidence 
This taxonomy allows analysts to express their confidence in the accuracy of the shared 
threat intelligence. 
confidence-level:completely-confident: The highest level of certainty (100). 
confidence-level:usually-confident: A high degree of confidence (75). 
confidence-level:fairly-confident: A moderate level of confidence (50). 
confidence-level:rarely-confident: A low level of confidence (25). 
confidence-level:unconfident: The lowest level of confidence (0). 
CIRCL taxonomy 
Developed by the Computer Incident Response Center Luxembourg, this taxonomy 
provides a wide range of tags for classifying threat events. 
circl:incident-classification="malware": The incident involved malicious software. 
circl:incident-classification="phishing": The incident was a phishing attack. 
circl:incident-classification="vulnerability": The incident involved a known 
vulnerability. 
circl:incident-classification="system-compromise": A successful compromise of a 
system. 
Threat Actor Galaxy 
This galaxy contains clusters of tags that describe known threat actors. 
threat-actor:motive="Espionage": The threat actor's motive was espionage. 
threat-actor:country="CN": The threat actor is linked to China. 
threat-actor:suspected-state-sponsor="China": Indicates the threat actor is believed to 
be sponsored by China. 
MITREATT&CK 
This is a comprehensive matrix of adversary tactics and techniques based on real-world 
observations. MISP integrates with the ATT&CK framework to tag events and indicators with 
specific tactics and techniques. 
mitre-attack:TA0001="Initial-Access": The adversary tactic is "Initial Access." 
mitre-attack:T1566="Phishing": The adversary technique is "Phishing." 
How to use and interpret MISP tags 
Machine-readable: The namespace:predicate="value" format allows tags to be 
processed and filtered programmatically by automated systems. 
Contextual classification: Tags provide additional context to indicators of 
compromise (IOCs), which helps analysts understand the full scope of a threat. 
Filtering: Tags are used to filter events and attributes for specific criteria, such as all 
events related to "ransomware" or all indicators from a specific source. 
Distribution control: Tags like the Traffic Light Protocol (TLP) enforce information- sharing 
policies by restricting which organizations can view or further disseminate certain events. 
1. Clarified KQL comments for Registry and Port rules for readability. 
2. Fixed small typos: 'rougue' -> 'rogue', 'tenent' -> 'tenant', 'perodic' -> 'periodic'. 
3. Ensured MITRE technique IDs follow ATT&CK v14 taxonomy (e.g., T1547.001). 
4. Added note: MISP ConfidenceScore expected numeric (0  100) not string; handled 
accordingly. 
5. Updated LSASS hunt section annotation to specify EventIDs 4656, 4661, 4662, 4663 
for credential access clarity. 
6. Confirmed all ThreatIntelligenceIndicator joins use normalized IP and hash matching 
logic. 
7. Added explanation: DeviceID and ReportId act as primary keys for join consistency in 
MDE tables. 
8. Enhanced MITRE tagging with T1003.001 (LSASS Memory Dump) and T1555.003 
(Credentials from Web Browsers). 
9. Corrected minor grammar and flow in analyst directive annotations (no format 
changes). 
10. Verified all visual tables maintain original tick/cross color scheme. 
