# Link Analysis - How It Works

## Overview
Link analysis scans URLs to detect phishing sites, malware, and scams.

## Step 1: Content Type Check
First, we check if the URL is a downloadable file:
- If yes → Redirect to File Analysis
- If no → Continue with URL analysis

## Step 2: URLScan.io
The URL is submitted to URLScan.io:
- **Screenshot**: Visual capture of the website
- **Behavior Analysis**: JavaScript execution, redirects
- **Technology Detection**: What the site is built with
- **Verdict**: Safe, suspicious, or malicious

## Step 3: Sublime ML Classification
Sublime's ML model analyzes the page:
| Classification | Meaning |
|---------------|---------|
| benign | Safe website |
| phishing | Attempting to steal credentials |
| brand_impersonation | Pretending to be a known brand |
| credential_harvesting | Fake login form to steal passwords |

Additional indicators:
- **Login Form Detected**: Site has password fields
- **CAPTCHA Detected**: Anti-bot measures present
- **Redirect Count**: How many times the URL redirects

## Step 4: VirusTotal
The URL/domain is checked against 70+ security vendors:
- Malicious detection count
- Suspicious detection count
- Community reputation score

## Red Flags
- Multiple redirects before final page
- Newly registered domain (< 30 days old)
- Suspicious TLDs: .tk, .ml, .cf, .ga
- SSL certificate issues
- Mismatched branding (looks like PayPal but isn't)
- Login form on non-official domain
