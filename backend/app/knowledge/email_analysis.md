# Email Analysis - How It Works

## Overview
PhishCheck uses a multi-stage pipeline to analyze emails for phishing threats.

## Step 1: Email Parsing
The .eml file is parsed to extract:
- **Headers**: From, To, Subject, Date, Reply-To, Message-ID
- **Body**: Plain text and HTML content
- **Attachments**: Filename, type, size, and file hash
- **URLs**: All links found in the email body
- **QR Codes**: Scanned for hidden URLs

## Step 2: Authentication Checks
We verify email authenticity:
- **SPF (Sender Policy Framework)**: Is the sender's IP authorized by the domain?
- **DKIM (DomainKeys Identified Mail)**: Is the email signature valid?
- **DMARC**: What's the domain's policy for failed SPF/DKIM?

Pass = legitimate sender, Fail = potentially spoofed

## Step 3: Sublime Security Analysis
The email is sent to Sublime Security's ML platform:
- Runs 100+ detection rules for phishing patterns
- Generates insights about suspicious indicators
- Calculates the **Attack Score (0-100)**

## Step 4: Attack Score Explained
The attack score is calculated by Sublime's ML model:
| Score | Level | Meaning |
|-------|-------|---------|
| 0-20 | Safe | No threats detected |
| 20-40 | Low | Minor concerns, proceed carefully |
| 40-70 | Medium | Multiple suspicious indicators |
| 70-100 | High | Do NOT interact with this email |

## Step 5: Threat Intelligence
URLs and IPs found in the email are checked:

**VirusTotal** - Checks against 70+ antivirus engines
**URLScan.io** - Takes screenshots, analyzes website behavior
**IPQualityScore** - Checks IP reputation and fraud scores
**Hybrid Analysis** - Sandbox analysis for attachments

## Common Detection Rules
- Sender impersonation (pretending to be someone else)
- Brand impersonation (fake Microsoft, PayPal, etc.)
- Urgency language ("Act now!", "Your account will be suspended")
- Suspicious link patterns (lookalike domains)
- Dangerous attachment types (.exe, .js, .scr)
