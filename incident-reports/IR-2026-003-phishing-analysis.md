# IR-2026-003 | Phishing Email Forensic Analysis

**Date:** April 20, 2026  
**Analyst:** Morgan Roberts  
**Severity:** High  
**Status:** Closed, IOCs Documented  
**MITRE ATT&CK:** T1566 Phishing

---

## Summary

A phishing email impersonating PayPal was analyzed using emlAnalyzer and manual header inspection. The email used multiple deception techniques including a typosquatted sender domain, mismatched Reply-To address, urgency-based social engineering, and a credential harvesting URL hosted directly on the attacker IP. Attacker infrastructure was investigated via VirusTotal revealing a Lithuanian bulletproof hosting provider with zero vendor detections, consistent with freshly provisioned phishing infrastructure.

---

## Environment

| Detail | Value |
|--------|-------|
| Analysis Tools | emlAnalyzer, VirusTotal, Manual Header Inspection |
| Sample Type | PayPal Impersonation Email |
| Analysis Host | Ubuntu Linux VM |
| Log Source | Email headers and body |

---

## Email Details

| Field | Value |
|-------|-------|
| From | support@paypa1-secure.com |
| Reply-To | support@paypa1-accounts-verify.net |
| Received From | mail.paypa1-secure.com (185.234.219.17) |
| Date | Mon, 20 Apr 2026 09:15:00 -0500 |
| MIME-Version | 1.0 |
| Content-Type | text/html |

---

## IOCs Extracted

| IOC Type | Value | Notes |
|----------|-------|-------|
| Sender Domain | paypa1-secure.com | Typosquatted "paypal" replaced with "paypa1" |
| Reply-To Domain | paypa1-accounts-verify.net | Mismatched from sender, misdirection technique |
| Originating IP | 185.234.219.17 | Lithuanian bulletproof hosting AS211415 |
| Credential URL | http://185.234.219.17/paypal/login.php | IP-direct hosting no legitimate domain |

---

## Investigation

### Step 1: Header Analysis with emlAnalyzer
Ran emlAnalyzer against the email sample to extract headers and URLs:

**Key findings:**
- Sender domain `paypa1-secure.com` does not match legitimate PayPal domain `paypal.com`
- Reply-To address redirects to different domain than sender, classic misdirection
- Email originated directly from IP `185.234.219.17` no legitimate mail infrastructure

### Step 2: Typosquatting Analysis
| Legitimate | Malicious | Technique |
|------------|-----------|-----------|
| paypal.com | paypa1-secure.com | Number substitution (l → 1) |
| paypal.com | paypa1-accounts-verify.net | Number substitution + extra subdomain |

### Step 3: URL Analysis
Credential harvesting URL identified:
`http://185.234.219.17/paypal/login.php`

Hosted directly on attacker IP, bypasses domain reputation checks. Path `/paypal/login.php` designed to appear legitimate to victims.

### Step 4: VirusTotal Investigation
IP `185.234.219.17` investigated via VirusTotal:

| Field | Value |
|-------|-------|
| ASN | AS211415 |
| Hosting Provider | Lithuanian bulletproof hosting |
| Routed Through | Austria |
| Vendor Detections | 0 out of 94 |
| Assessment | Freshly provisioned phishing infrastructure |

Zero detections across 94 vendors indicates the IP was recently provisioned, a common technique to evade reputation-based blocking.

---

## TTPs Identified

| TTP | Description |
|-----|-------------|
| Typosquatting | Sender domain mimics PayPal using number substitution |
| Reply-To Misdirection | Reply-To differs from sender to redirect victim responses |
| Urgency-Based Social Engineering | Email content designed to pressure immediate action |
| IP-Direct Hosting | Credential page hosted on raw IP to evade domain filtering |
| Bulletproof Hosting | Infrastructure hosted with provider known for ignoring abuse reports |

---

## Findings

- Email is a confirmed phishing attempt impersonating PayPal
- Multiple deception layers used typosquatting, misdirection, urgency
- Credential harvesting page hosted on bulletproof hosting infrastructure
- Zero VirusTotal detections suggests freshly provisioned infrastructure
- No legitimate PayPal infrastructure involved in email delivery

---

## Recommendations

1. Block sender domains `paypa1-secure.com` and `paypa1-accounts-verify.net` at email gateway
2. Block IP `185.234.219.17` at perimeter firewall
3. Search email logs for any other recipients of this campaign
4. Alert users who may have clicked the credential harvesting URL
5. Implement DMARC, DKIM, and SPF validation to detect spoofed sender domains
6. Deploy email security gateway with URL sandboxing capabilities

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|-----------|-----|
| Initial Access | Phishing | T1566 |
| Credential Access | Phishing for Information | T1598 |
| Resource Development | Acquire Infrastructure | T1583 |
