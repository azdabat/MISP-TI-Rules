# CTI Hunts & KQL Rules — Ala Dabat

KQL threat-hunting rules with **adaptive scoring** and **MISP/OpenCTI enrichment**. Each rule includes commented headers, MITRE mappings, and embedded hunter directives.

## Files
- 01_DLL_Sideloading_Adaptive.kql
- 02_Registry_Persistence_MISP_Enriched.kql
- 03_Suspicious_Ports_with_External_CSV.kql
- 04_SMB_Lateral_NotPetya_Style.kql
- 05_OAuth_Consent_Abuse.kql
- 06_Rogue_Endpoint_ZeroTrust.kql
- 07_BEC_Clickthrough_Enriched.kql

## Scoring
FinalScore = (Detection * 0.4) + (IntelConfidence * 0.3) + (KillChain * 0.2) + (Temporal * 0.1)
Risk: CRITICAL ≥ 90 | HIGH ≥ 70 | MEDIUM ≥ 50

## Integration
- MISP ↔ Sentinel via TAXII 2.x → `ThreatIntelligenceIndicator`
- Sightings → MISP (manual/SOAR) → OpenCTI graphs (actors/TTPs, first/last seen)
