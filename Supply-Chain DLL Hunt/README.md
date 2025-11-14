L3 Native Hunt — Supply-Chain DLL / Signed Binary Drift (TI-Aware)

Author: Ala Dabat
Platform: Microsoft Defender for Endpoint (MDE) & Microsoft Sentinel
Rule Type: L3 Threat Hunt / Low-Noise Analytic
Scope: DLL sideloading, signed binary drift, long-dormant loaders, registry/driver/network correlation, TI/MISP aware
MITRE: TA0003 Persistence • TA0005 Defense Evasion • TA0011 C2
Techniques: T1574.002 • T1553.002 • T1547.006

🎯 Detection Goal

This analytic identifies supply-chain compromise patterns and malicious DLL sideloading inside otherwise legitimate, trusted vendor processes.

The detector correlates:

DLL ImageLoad events into vendor processes

File creation → load timing

Immediate loaders (≤5 minutes)

Slow delayed loaders (hours → days → weeks)

Integrity drift from enterprise baselines

Version drift

Signer drift

Hash drift

Registry persistence containing DLL paths

Driver drops (.sys) occurring near the DLL activation

Network activity (outbound IP, URL, domain)

TI/MISP/OpenCTI indicators for hash, IP, domain, URL

This behaves as a full-chain supply-chain threat detector, not just “DLL loaded”.

✅ What This Rule Detects
Detection Area	Covered	Explanation
DLL sideloading into trusted vendor processes	✔ Yes	Targets processes like 3cx.exe, SolarWinds.BusinessLayerHost.exe, bigip_service.exe, etc.
Immediate loader DLLs (≤ 5 min after drop)	✔ Yes	Catches “drop → execute” behaviour used in 3CX/CCleaner.
Delayed loaders (minutes → hours → 7 days)	✔ Yes	Tracks staged supply-chain activation.
Long-dormant loaders (1–30 days)	✔ Yes	Detects SolarWinds-style long-delay implants.
Rare DLLs across org	✔ Yes	Flags DLLs seen on ≤2 devices.
Unsigned or untrusted DLLs	✔ Yes	IsUnsigned & TrustedSigner scoring.
Integrity drift (version/signer/hash)	✔ Yes	Core indicator of supply-chain tampering.
Registry autoruns referencing DLLs	✔ Yes	COM, Run keys, LSA, AppInit_DLLs, Services.
Driver drops (.sys) near DLL load	✔ Yes	Detects kernel-level persistence.
Suspicious network (IP/URL/Domain)	✔ Yes	Correlates C2 via NetCtx + TI.
Malicious DLL hash in MISP/OpenCTI	✔ Yes	TIFile join uses hash confidence/score.
Known APT C2 domains/IPs	✔ Yes	TINet join enriches final score.
🧨 How It Maps to Real Supply-Chain Attacks
3CX Supply-Chain Backdoor

Attack behaviours observed:

Malicious DLL dropped in AppData

DLL loaded by 3cx.exe

Stage-2 executed after a delay

C2 communication over HTTP(S)

Known malicious hashes

Detector coverage:

✔ DLL loaded into trusted vendor binary

✔ Immediate or delayed loader scored

✔ Integrity drift (hash mismatch)

✔ Network C2 + TI correlation

✔ MISP IOC match → high TI score

SolarWinds SUNBURST

Observed behaviours:

Malicious Orion DLL with forged certificate

Very long dormant execution

Integrity drift of version + hash

Network connections to attacker infra

Strong TI coverage (hash + domains)

Detector coverage:

✔ DormantLong / DormantVeryLong

✔ Hash/Version/Signer drift

✔ C2 domain correlation

✔ TI scoring → CRITICAL

F5 BIG-IP / Appliance Backdoor

Observed behaviours:

DLL or EXE loaded by F5 helper processes

Driver dropped in the system directory

Rare binary across org

Network beacons outward

Detector coverage:

✔ VendorProcesses: bigip_service.exe

✔ Rare DLL across org

✔ DriverPath → KillChainScore

✔ TI network indicator match

NotPetya / M.E.Doc Backdoor

Observed behaviours:

Signed binary drift

DLL tampering inside trusted vendor path

Malicious C2 traffic

Lateral movement

Detector coverage:

✔ Hash/Signer drift

✔ Rare DLL

✔ Network TI correlation

✔ Registry references to DLL loaders

🧠 Why Quick DLL Load Is Suspicious

This rule’s FastLoad metric detects DLLs that are:

Dropped → Loaded within 300 seconds (5 minutes)


Attackers use fast-loading DLLs because:

They execute before AV cloud scanning catches them

They mimic legitimate vendor DLL loads

They allow quick post-exploitation

They support supply-chain payload activation

They are common in 3CX, CCleaner, and NotPetya campaigns

FastLoad is treated as high confidence malicious behaviour (score multiplier = 3).

📊 Scoring Model Breakdown
BehaviorScore (40%)
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
-1 × TrustedSigner

KillChainScore (20%)
+1 if driver loaded
+1 if registry key references DLL

RecencyScore (10%)
+10 if DLL loaded in last 24h

TI_Confidence (30%)

Hash IOC confidence

IP/URL/Domain IOC confidence

Combined:

FinalScore = BehaviorScore*0.4
           + TI_Confidence*0.3
           + KillChainScore*0.2
           + RecencyScore*0.1

🧭 Hunter Directives (Embedded in Rule Output)

Each output row includes an array of human-readable triage steps:

Confirm which vendor process loaded the DLL

Validate signer/signer drift

Confirm version/hash drift from baseline

Review timing (fast-load vs dormant-load)

Check registry and driver activity

Pivot on network traffic

Check TI (hash/IP/domain) matches

For ALERT: isolate host, collect memory, compare against vendor baseline
