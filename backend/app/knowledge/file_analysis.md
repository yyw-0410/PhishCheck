# File Analysis - How It Works

## Overview
File analysis checks uploaded files or hashes against malware databases.

## Step 1: Hash Calculation
When you upload a file, we calculate:
- **SHA256**: Primary identifier (64 characters)
- **MD5**: Legacy hash (32 characters)
- **SHA1**: Additional verification (40 characters)

You can also just enter a hash if you already have one.

## Step 2: VirusTotal Lookup
The file hash is checked against VirusTotal:
- **70+ antivirus engines** scan results
- Detection stats: malicious, suspicious, harmless counts
- File metadata: type, size, first seen date
- Known names for the file
- Sandbox verdicts from multiple vendors

## Step 3: Hybrid Analysis
The hash is checked in Hybrid Analysis sandbox database:
- **Dynamic behavior analysis** from sandboxed execution
- **Threat Score**: 0-100%
- **AV Detections**: How many AV engines flagged it
- **Malware Family**: Known malware name (if detected)
- **Network Activity**: Domains/IPs contacted
- **MITRE ATT&CK**: Attack techniques used

## Risk Score Calculation
The final risk score (0-100) is calculated:

| Source | Points |
|--------|--------|
| VT malicious detection | 15 base + 10 per detection (max 60) |
| VT suspicious detection | 3 per detection (max 15) |
| HA threat score | 0-50 points (scaled from 0-100%) |
| HA malicious verdict | +25 points |
| HA suspicious verdict | +10 points |
| Malware family detected | +20 points |
| HA AV detections | 15 + 5 per detection (max 45) |

## Verdicts
| Score | Verdict | Meaning |
|-------|---------|---------|
| 0-39 | clean | No threats detected |
| 40-69 | suspicious | Some concerning indicators |
| 70-100 | malicious | Confirmed malware |
| N/A | not_found | File not in any database |
