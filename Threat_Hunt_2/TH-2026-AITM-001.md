# Threat Hunting Report: Adversary-in-the-Middle (AiTM) Phishing

![Threat Hunting](https://img.shields.io/badge/Project-Threat%20Hunting-blue)
![Threat](https://img.shields.io/badge/Threat-AiTM%20Phishing-red)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-T1557-orange)
![Identity](https://img.shields.io/badge/Focus-Identity%20%26%20Token%20Theft-purple)
![Microsoft Sentinel](https://img.shields.io/badge/SIEM-Microsoft%20Sentinel-blue)
![Status](https://img.shields.io/badge/Status-Simulated%20Hunt-yellow)

> **Report type:** Proactive Threat Hunt  
> **Primary focus:** Adversary-in-the-Middle phishing, session/token theft, MFA interception, and post-compromise identity abuse  
> **Primary target:** Microsoft Entra ID / Microsoft 365 environments  
> **Applicable industries:** Financial Services, FinTech, SaaS, Technology, Healthcare, Government, Cryptocurrency/Web3, and large enterprises

---

## 1. Executive Summary

### Report Title

**Threat Hunt Report: Detection of Adversary-in-the-Middle (AiTM) Phishing and Session Token Compromise**

### Purpose of the Hunt

This threat hunt investigates the hypothesis that an adversary may use **Adversary-in-the-Middle (AiTM) phishing** to proxy a victim's authentication session, capture credentials and authentication/session tokens, and subsequently access cloud applications as the legitimate user.

Unlike conventional credential phishing, AiTM phishing can place attacker-controlled infrastructure between the victim and a legitimate authentication service. The attacker can relay the authentication flow in real time and capture session material after the victim successfully authenticates.

Microsoft documented a large 2026 campaign that used multi-stage social engineering, CAPTCHA/staging pages, and an AiTM phishing flow to capture authentication tokens. Between **April 14 and April 16, 2026**, Microsoft observed the campaign targeting more than **35,000 users across more than 13,000 organizations in 26 countries**, with healthcare/life sciences, financial services, professional services, and technology/software among the most affected sectors. [1]

Microsoft also reported in March 2026 that the **Tycoon2FA** AiTM phishing kit was being operated at scale and provided advanced-hunting guidance for identifying potentially compromised identities. [2]

### Hunt Scope

The hunt focuses on:

- Phishing email and URL telemetry
- Browser and web-proxy activity
- Microsoft Entra authentication
- Session and token anomalies
- MFA-related activity
- Device compliance and trust
- Microsoft 365 activity
- Inbox-rule creation
- OAuth/application activity
- Endpoint telemetry
- Cloud/SaaS data access

### Key Findings Summary

> **Important:** This repository documents a **simulated threat-hunting exercise**. The findings below are hunting scenarios and example observations, not evidence that a real organization was compromised.

| ID | Simulated Finding | Target | Severity |
|---|---|---|---|
| **F-001** | User clicked a suspicious phishing URL followed by an anomalous sign-in | User identity | High |
| **F-002** | Authentication originated from an unmanaged/new device with suspicious sign-in properties | User identity | High |
| **F-003** | Session/token anomaly consistent with AiTM activity | Cloud session | Critical |
| **F-004** | Successful cloud access occurred after the suspected AiTM authentication event | Microsoft 365 | Critical |
| **F-005** | Inbox rule created after suspicious session activity | Exchange Online | High |
| **F-006** | Unusual SaaS/cloud data access followed suspected session compromise | Microsoft 365/SaaS | High |
| **F-007** | Phishing infrastructure displayed characteristics associated with an AiTM/PhaaS campaign | Email/Web | High |

### Overall Assessment

**Threat level: HIGH**

The primary risk is not simply credential theft. The more significant concern is **session/token theft**, which can allow an attacker to operate as an authenticated user and potentially bypass authentication controls that are not phishing-resistant.

---

## 2. Hunt Details

| Field | Value |
|---|---|
| **Hunt ID** | TH-2026-AITM-001 |
| **Hunt Name** | Adversary-in-the-Middle Phishing |
| **Start Date** | August 2026 |
| **End Date** | August 2026 |
| **Lead Analyst** | SOC / Threat Hunting Team |
| **Hunt Type** | Proactive / Intelligence-led |
| **Priority** | High |
| **Primary Platform** | Microsoft Entra ID / Microsoft 365 |
| **SIEM** | Microsoft Sentinel |
| **Endpoint** | Microsoft Defender for Endpoint |
| **Identity Security** | Microsoft Entra ID Protection |
| **Data Sources** | Entra Sign-in Logs, Entra Audit Logs, Defender XDR, Microsoft 365 Unified Audit Log, Defender for Office 365, proxy/DNS, endpoint telemetry |
| **Frameworks** | MITRE ATT&CK, threat-intelligence-led hunting |

The structure follows the supplied Hunt.io Threat Hunter's Report Template, which recommends documenting the hunt purpose, scope, data sources, hypothesis, methodology, findings, detailed analysis, IOCs, intelligence gaps, ATT&CK mapping, detection opportunities, recommendations, references, and sensitivity. [Template]

---

## 3. Hypothesis or Trigger

### Primary Hypothesis

> **An adversary may deliver a phishing link that directs a victim to attacker-controlled AiTM infrastructure, proxies the legitimate authentication process, captures credentials and session/token material, and subsequently replays the authenticated session to access enterprise cloud resources.**

### Secondary Hypotheses

#### H1 — Phishing Delivery

An attacker may deliver an email containing a malicious or compromised URL that ultimately redirects the user to AiTM infrastructure.

#### H2 — Authentication Proxying

The victim may authenticate successfully while the attacker proxies the authentication flow between the victim and the legitimate identity provider.

#### H3 — Session/Token Theft

The attacker may capture an authenticated session cookie or other authentication token.

#### H4 — MFA Interception

The attacker may relay or intercept a non-phishing-resistant MFA flow in real time.

#### H5 — Session Replay

The attacker may reuse stolen session material from a different IP, device, geography, or browser.

#### H6 — Post-Compromise Abuse

The compromised session may be used for:

- Business Email Compromise
- Inbox-rule creation
- Mailbox reconnaissance
- Internal phishing
- SaaS data collection
- Cloud resource access
- Financial fraud
- Further credential theft

---

## 4. Threat Intelligence Context

### 4.1 Current Threat Landscape

Microsoft's April 2026 threat research described a multi-stage phishing campaign that ultimately used an AiTM flow to proxy authentication and capture authentication tokens. The campaign targeted more than 35,000 users across more than 13,000 organizations in 26 countries. [1]

Microsoft's Q1 2026 email threat report also identified approximately **8.3 billion email-based phishing threats** during January–March 2026. Microsoft reported that QR-code phishing more than doubled during the quarter, while link-based threats represented the majority of email threats. [3]

### 4.2 Tycoon2FA

Microsoft's March 2026 research into **Tycoon2FA** describes an AiTM phishing kit operating at scale. Microsoft documented detections around suspicious sign-ins, session-cookie replay, and post-compromise activity. [2]

The research provides a particularly useful hunting model:

```text
Phishing Email
      |
      v
AiTM Phishing Page
      |
      v
Victim Authentication
      |
      v
Credential + Session Token Capture
      |
      v
Attacker Session Replay
      |
      v
Microsoft 365 / Cloud Access
      |
      +----------------------+
      |                      |
      v                      v
Mailbox Access          Data Access
      |                      |
      v                      v
Inbox Rules             Collection
      |
      v
BEC / Internal Phishing
```

### 4.3 Why Conventional MFA May Not Be Enough

Microsoft explains that AiTM attacks can capture authentication/session material during a proxied authentication flow, allowing attackers to use the resulting session and potentially bypass MFA protections that are not phishing-resistant. [4]

Microsoft's current token guidance also identifies AiTM as a token-theft attack vector and recommends monitoring suspicious token behavior and deploying phishing-resistant authentication. [4][5]

---

## 5. Target Industries and Attack Objectives

| Industry | Likely Target | Potential Objective |
|---|---|---|
| **Financial Services** | Employees, finance teams, executives | BEC, financial fraud, payment manipulation |
| **FinTech** | Developers, administrators, finance teams | Cloud access, API/token theft, fraud |
| **Cryptocurrency / Web3** | Developers, wallet administrators, executives | Cloud/API compromise, wallet-related fraud |
| **SaaS** | Administrators, developers, support teams | Customer-data access |
| **Technology** | Developers, cloud admins | Source-code/cloud access |
| **Healthcare** | Clinical/admin users | Sensitive data access, BEC, ransomware staging |
| **Government** | Privileged users and officials | Espionage, data access |
| **Enterprise** | Executives and privileged users | BEC, lateral access, data theft |

---

## 6. Methodology

The methodology follows the structure recommended by the supplied Hunt.io template and combines threat intelligence, MITRE ATT&CK mapping, identity analytics, email analysis, endpoint correlation, and cloud/SaaS investigation. [Template]

### Investigation Flow

```text
Threat Intelligence
        |
        v
Define AiTM Hypothesis
        |
        v
Identify Phishing Events
        |
        v
URL / Domain Analysis
        |
        v
Correlate User Click
        |
        v
Analyze Entra Authentication
        |
        v
Analyze Session / Token Indicators
        |
        v
Correlate Device + IP + Geography
        |
        v
Investigate Microsoft 365 Activity
        |
        v
Check Inbox Rules / Mailbox Access
        |
        v
Check OAuth / Application Activity
        |
        v
Determine Post-Compromise Behavior
        |
        v
MITRE Mapping + Detection Engineering
```

### Investigation Questions

The hunt attempts to answer:

1. Did the user receive a suspicious phishing message?
2. Did the user click or navigate to a suspicious URL?
3. Did authentication occur shortly afterward?
4. Was the device unmanaged or previously unseen?
5. Did Entra generate an **Attacker in the Middle**, **Anomalous Token**, or related risk signal?
6. Did a new session appear from an unusual IP or geography?
7. Was the same account used from different devices in a short period?
8. Did the account create inbox rules after the suspicious authentication?
9. Did the user access unusual SaaS resources?
10. Was there evidence of bulk data access or exfiltration?
11. Was an OAuth application or service principal modified?
12. Does the activity correlate with a known PhaaS/AiTM campaign?

---

## 7. Data Sources

| Data Source | Hunting Purpose |
|---|---|
| **Microsoft Defender for Office 365** | Phishing email, URL, campaign, click telemetry |
| **Microsoft Entra Sign-in Logs** | Authentication analysis |
| **Microsoft Entra ID Protection** | Risk detections and identity compromise signals |
| **Microsoft Entra Audit Logs** | Identity/application changes |
| **Microsoft 365 Unified Audit Log** | Mailbox, SharePoint, OneDrive and SaaS activity |
| **Microsoft Defender XDR** | Cross-domain correlation |
| **Microsoft Defender for Endpoint** | Browser and endpoint telemetry |
| **Defender for Cloud Apps** | Cloud/SaaS anomaly and session activity |
| **DNS Logs** | Domain resolution and infrastructure correlation |
| **Proxy Logs** | URL access and web-session analysis |
| **Firewall Logs** | Network connection analysis |
| **Email Gateway** | Sender, URL, authentication and message metadata |
| **Threat Intelligence Platform** | Domain/IP/campaign enrichment |

---

## 8. Key Findings

> The following findings are **simulated** and demonstrate how an analyst should document AiTM hunting results.

| ID | Indicator / Behavior | Meaning | Affected Asset | ATT&CK | Severity |
|---|---|---|---|---|---|
| **F-001** | Phishing URL followed by authentication | Potential AiTM delivery chain | User endpoint | T1566.002 / T1598.003 | High |
| **F-002** | New/unmanaged device sign-in | Possible attacker session | User account | T1078 | High |
| **F-003** | Anomalous token / AiTM risk signal | Possible session-token compromise | Cloud identity | T1539 / T1557 | Critical |
| **F-004** | Session replay from unusual IP/device | Possible stolen session | Microsoft 365 | T1539 | Critical |
| **F-005** | Inbox rule created after suspicious session | Possible BEC persistence | Exchange Online | T1098 / T1114 | High |
| **F-006** | Bulk cloud-file/mailbox access | Potential collection | SaaS | T1530 / T1114 | High |
| **F-007** | Suspicious phishing infrastructure | Potential AiTM/PhaaS campaign | Email/Web | T1566.002 | High |

---

## 9. Detailed Analysis

## F-001 — Phishing URL Followed by Authentication

### Observation

A user receives a phishing email and accesses a URL that eventually redirects to a suspicious authentication page.

### Expected Sequence

```text
Email Received
      |
      v
User Clicks URL
      |
      v
Redirect / Staging Infrastructure
      |
      v
CAPTCHA / Browser Verification
      |
      v
AiTM Authentication Page
      |
      v
User Authenticates
```

### Why It Matters

Microsoft observed a 2026 campaign using multiple staging pages and CAPTCHA mechanisms before directing users to an AiTM authentication flow. [1]

### Investigation

Correlate:

- Sender
- Sender domain
- Reply-to domain
- URL
- Final URL
- Redirect chain
- Time of click
- User identity
- Authentication event
- Source IP
- Device
- Browser

---

## F-002 — Authentication from New or Unmanaged Device

### Observation

The account successfully authenticates shortly after visiting a suspicious URL, but the sign-in originates from a device that is:

- Unmanaged
- Non-compliant
- Previously unseen
- Missing expected device identifiers

### Hunting Logic

```text
Suspicious URL Click
        +
Successful Browser Sign-in
        +
Unmanaged Device
        +
Unknown / New IP
```

### Risk

**High**

Microsoft's Tycoon2FA research provides an example of hunting for potentially compromised identities using browser sign-ins with medium/high risk, missing device trust, and missing device identifiers. [2]

---

## F-003 — Anomalous Token / AiTM Risk Signal

### Observation

The identity provider reports a risk signal consistent with token/session compromise.

Relevant Microsoft Entra risk detections include:

- **Anomalous Token**
- **Attacker in the Middle**
- **Unfamiliar sign-in properties**
- **Malicious IP address**
- **Suspicious browser**

Microsoft lists these detections as relevant identity-risk signals in current phishing-resistant authentication guidance. [5]

### Investigation

Search for:

```text
Risk Detection
        |
        +--> User
        |
        +--> Session ID
        |
        +--> IP
        |
        +--> Application
        |
        +--> Device
        |
        +--> Authentication Event
```

Microsoft documents linkable identifiers that allow analysts to correlate authentication artifacts, including access tokens, refresh tokens, and session cookies, back to a root authentication event. [6]

---

## F-004 — Possible Session Replay

### Observation

The same user account shows authenticated activity from an unexpected device or network shortly after a suspicious authentication event.

### Example Timeline

```text
10:01  User receives phishing email
10:04  User clicks suspicious URL
10:05  User authenticates
10:06  Session/token risk generated
10:09  Same account accessed from new IP
10:10  Microsoft 365 access
10:12  Inbox accessed
```

### Risk

**Critical**

Session replay is especially concerning because the attacker may not need to repeat the full authentication process.

MITRE's **T1539 — Steal Web Session Cookie** describes theft and use of web session cookies to access web applications as an authenticated user, including scenarios where cookies can bypass some MFA mechanisms. [7]

---

## F-005 — Inbox Rule Creation

### Observation

An inbox rule is created shortly after suspected session compromise.

### Why It Matters

Attackers may use mailbox rules to:

- Hide security notifications
- Redirect messages
- Hide replies
- Monitor financial communications
- Facilitate BEC
- Maintain visibility into internal communications

### Correlation

```text
AiTM Risk
   +
New Session
   +
Mailbox Access
   +
New Inbox Rule
```

= **High-confidence post-compromise investigation**

Microsoft's current Defender documentation provides an investigation pattern that correlates suspicious token/session IDs with `New-InboxRule` activity. [8]

---

## F-006 — SaaS / Cloud Data Access

### Observation

The compromised identity accesses substantially more data than its normal baseline.

### Example

```text
Normal:
10–50 files/day

Observed:
1,500+ files
+
New IP
+
New Device
+
Suspicious Session
```

### Investigate

- SharePoint downloads
- OneDrive downloads
- Mailbox searches
- Mailbox exports
- External sharing
- Teams access
- Sensitive file access
- Cloud storage enumeration

MITRE maps cloud storage collection to **T1530 — Data from Cloud Storage**. [9]

---

## F-007 — Suspicious AiTM/PhaaS Infrastructure

### Infrastructure indicators to investigate

- Newly registered domains
- Lookalike domains
- Typosquatted domains
- Suspicious subdomains
- Short-lived hosting
- Reverse-proxy infrastructure
- TLS certificate anomalies
- Redirect chains
- CAPTCHA/staging pages
- Browser-in-the-browser pages
- Login pages visually matching enterprise identity providers

MITRE documents **Evilginx2** as an AiTM framework capable of operating as a reverse proxy to capture credentials, authentication tokens, and session cookies. [10]

---

## 10. Indicators of Compromise

The report template recommends separating IOCs into categories so they can be reused during detection and incident response. [Template]

### 10.1 Network / Infrastructure IOCs

> No real campaign IOCs are embedded in this simulated report. Populate these fields from validated threat-intelligence sources during an actual investigation.

| Type | Value | Confidence | Action |
|---|---|---|---|
| Domain | `<suspicious-domain>` | High | Investigate/block |
| URL | `<phishing-url>` | High | Block |
| IP | `<hosting-ip>` | Medium/High | Enrich/block if validated |
| ASN | `<suspicious-asn>` | Medium | Investigate |
| Certificate | `<certificate-fingerprint>` | Medium | Hunt |
| Redirect URL | `<redirect-url>` | High | Block/investigate |

### 10.2 Identity IOCs

| Type | Value |
|---|---|
| User | `<compromised-user>` |
| Session ID | `<suspicious-session-id>` |
| Device ID | `<unknown-device-id>` |
| IP | `<suspicious-source-ip>` |
| Application | `<suspicious-application>` |
| OAuth App ID | `<application-id>` |

### 10.3 Behavioral IOCs

- Suspicious phishing URL click followed by authentication
- Authentication from unmanaged device
- Authentication from unexpected geography
- Authentication from unusual ASN
- Anomalous token
- Attacker-in-the-Middle identity-risk detection
- Session replay
- New inbox rule after suspicious session
- Bulk mailbox access
- Bulk cloud-file downloads
- Unusual OAuth activity
- Suspicious internal email activity after account compromise

---

## 11. Intelligence Gaps

| Gap | Impact | Priority |
|---|---|---|
| URL click telemetry unavailable | Cannot establish phishing-to-login correlation | Critical |
| Incomplete Entra risk logs | Limited identity-risk visibility | Critical |
| No session identifiers | Difficult to correlate authentication and post-auth activity | High |
| Incomplete Defender XDR coverage | Reduced endpoint correlation | High |
| Limited SaaS audit logging | Data-access activity may be missed | High |
| No centralized proxy logs | Redirect-chain analysis is difficult | High |
| No DNS history | Infrastructure pivoting is limited | Medium |
| No email authentication telemetry | Spoofing analysis is weaker | Medium |
| No user/device baseline | Increased false positives | High |

### Recommended Gap Closure

```text
Email Security
      +
URL Click Telemetry
      +
Entra Identity Logs
      +
Session/Token Identifiers
      +
Endpoint Telemetry
      +
SaaS Audit Logs
      |
      v
Central SIEM
      |
      v
Identity Threat Hunting
```

---

## 12. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Hunting Application |
|---|---|---|---|
| **Initial Access** | Phishing | **T1566** | Initial phishing delivery |
| **Initial Access** | Phishing: Spearphishing Link | **T1566.002** | Malicious authentication URL |
| **Reconnaissance** | Phishing for Information: Spearphishing Link | **T1598.003** | Credential harvesting |
| **Credential Access** | Adversary-in-the-Middle | **T1557** | Authentication proxying / relay |
| **Credential Access** | Steal Web Session Cookie | **T1539** | Session-cookie theft |
| **Credential Access** | Multi-Factor Authentication Interception | **T1111** | MFA interception |
| **Persistence / Privilege** | Account Manipulation | **T1098** | Post-compromise identity changes |
| **Credential Access** | Steal Application Access Token | **T1528** | Token theft |
| **Collection** | Email Collection | **T1114** | Mailbox reconnaissance |
| **Collection** | Data from Cloud Storage | **T1530** | SaaS/cloud collection |
| **Defense Evasion** | Valid Accounts | **T1078** | Use of compromised identity |

MITRE's current phishing guidance explicitly identifies AiTM phishing kits such as EvilProxy and Evilginx2 as mechanisms that can proxy authentication and capture session cookies, potentially enabling MFA bypass through session-cookie use. [11]

---

## 13. Detection Opportunities

### 13.1 Phishing Click → Authentication Correlation

```text
IF
    User clicks suspicious URL
AND
    User authenticates within a short time window
AND
    Authentication is from unusual device/IP
THEN
    Generate High-Risk Identity Investigation
```

### 13.2 AiTM Identity-Risk Detection

```text
IF
    Entra risk event = "Attacker in the Middle"
OR
    Entra risk event = "Anomalous Token"
THEN
    Correlate:
        User
        Session ID
        IP
        Device
        Application
        Mailbox activity
        Cloud activity
```

### 13.3 Session Replay Detection

```text
IF
    Same user/session
AND
    Rapid change in:
        IP
        Country
        Device
        Browser
THEN
    Investigate potential session replay
```

### 13.4 Suspicious Token + Inbox Rule

```text
Suspicious Token
      +
New-InboxRule
      +
Unusual IP
```

**Severity: Critical**

### 13.5 Suspicious Session + Bulk Data Access

```text
Suspicious Session
      +
Large Mailbox Access
      OR
Large SharePoint/OneDrive Download
```

**Severity: Critical**

---

## 14. Microsoft Sentinel / KQL Hunting Queries

> **Note:** These queries are starting points. Production deployment requires validation against the tenant's available tables, schema, retention period, identity architecture, VPN/proxy design, and normal user behavior.

### 14.1 Suspicious Entra Sign-ins

```kusto
SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType == 0
| where IsRisky == true
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    Location,
    AppDisplayName,
    ClientAppUsed,
    DeviceDetail,
    RiskLevelDuringSignIn,
    RiskState,
    AuthenticationRequirement
| order by TimeGenerated desc
```

### 14.2 Unmanaged / Unknown Device Sign-ins

```kusto
SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType == 0
| where ClientAppUsed == "Browser"
| extend DeviceName = tostring(DeviceDetail.displayName)
| extend IsManaged = tostring(DeviceDetail.isManaged)
| extend IsCompliant = tostring(DeviceDetail.isCompliant)
| where IsManaged != "true" or IsCompliant != "true"
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    Location,
    AppDisplayName,
    DeviceName,
    IsManaged,
    IsCompliant,
    RiskLevelDuringSignIn
| order by TimeGenerated desc
```

### 14.3 MFA / Authentication Method Changes

```kusto
AuditLogs
| where TimeGenerated > ago(30d)
| where ActivityDisplayName has_any (
    "authentication method",
    "authentication",
    "MFA"
)
| project
    TimeGenerated,
    ActivityDisplayName,
    InitiatedBy,
    TargetResources,
    Result
| order by TimeGenerated desc
```

### 14.4 Suspicious Inbox Rule Creation

```kusto
CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType == "New-InboxRule"
| project
    Timestamp,
    AccountId,
    ActionType,
    IPAddress,
    Application,
    RawEventData
| order by Timestamp desc
```

### 14.5 OAuth / Application Changes

```kusto
AuditLogs
| where TimeGenerated > ago(30d)
| where ActivityDisplayName has_any (
    "Consent",
    "Add service principal",
    "Add application",
    "Update application"
)
| project
    TimeGenerated,
    ActivityDisplayName,
    InitiatedBy,
    TargetResources,
    Result
| order by TimeGenerated desc
```

### 14.6 Potentially Suspicious Browser Authentication

```kusto
SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType == 0
| where ClientAppUsed == "Browser"
| extend DeviceName = tostring(DeviceDetail.displayName)
| where isempty(DeviceName)
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    Location,
    AppDisplayName,
    ClientAppUsed,
    DeviceDetail,
    RiskLevelDuringSignIn,
    AuthenticationRequirement
| order by TimeGenerated desc
```

### 14.7 Authentication Followed by Inbox Rule

```kusto
let suspiciousUsers =
    SigninLogs
    | where TimeGenerated > ago(7d)
    | where ResultType == 0
    | where IsRisky == true
    | project UserPrincipalName;

CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType == "New-InboxRule"
| where AccountId in (suspiciousUsers)
| project
    Timestamp,
    AccountId,
    ActionType,
    IPAddress,
    Application,
    RawEventData
```

---

## 15. Risk Scoring Model

A single anomaly should not automatically mean compromise. The recommended approach is to correlate multiple weak signals.

| Indicator | Score |
|---|---:|
| Suspicious phishing URL click | +20 |
| New device | +20 |
| Unmanaged device | +15 |
| New country | +20 |
| New ASN | +10 |
| Entra "Attacker in the Middle" detection | +40 |
| Anomalous token | +40 |
| Suspicious session replay | +40 |
| MFA anomaly | +30 |
| New inbox rule | +25 |
| Bulk mailbox access | +30 |
| Bulk cloud download | +30 |
| Privileged account | +30 |
| Suspicious OAuth consent | +30 |

### Risk Classification

```text
0–29      Low
30–59     Medium
60–89     High
90–119    Critical
120+      Critical / Immediate IR
```

### Example

```text
Phishing URL Click       +20
New Device               +20
Unmanaged Device         +15
AiTM Risk Detection      +40
New Inbox Rule           +25
Bulk Mailbox Access      +30
--------------------------------
Total                    150
```

**Result: CRITICAL**

---

## 16. Investigation Playbook

### Step 1 — Validate the Phishing Event

Collect:

- Sender
- Sender IP
- Sender domain
- Reply-to
- URL
- Final destination
- Redirect chain
- Email headers
- Authentication results
- User click timestamp

### Step 2 — Identify the Victim

Determine:

- User
- Department
- Privilege level
- Executive/finance role
- Device
- Location
- Normal authentication pattern

### Step 3 — Investigate Authentication

Check:

- IP
- ASN
- Country
- Device
- Browser
- Client application
- Authentication method
- MFA requirement
- Risk state
- Risk level

### Step 4 — Correlate Session

Use available:

- Session ID
- Correlation ID
- Token identifiers
- Root authentication event
- Cloud session identifiers

Microsoft documents linkable identifiers specifically to help investigators correlate authentication artifacts back to a root authentication event. [6]

### Step 5 — Investigate Post-Compromise Activity

Search for:

- Inbox rules
- Mailbox access
- Email forwarding
- Internal phishing
- External email activity
- SharePoint downloads
- OneDrive downloads
- OAuth consent
- Cloud administrative activity

### Step 6 — Determine Scope

Identify:

```text
Compromised User
        |
        +--> Sessions
        |
        +--> Devices
        |
        +--> IPs
        |
        +--> Applications
        |
        +--> Mailboxes
        |
        +--> Cloud Resources
        |
        +--> Data Access
```

### Step 7 — Containment

When compromise is confirmed:

- Revoke active sessions/tokens
- Reset credentials
- Revoke malicious OAuth grants
- Remove unauthorized MFA methods
- Disable compromised accounts when necessary
- Block phishing URLs/domains
- Block malicious sender infrastructure
- Remove malicious inbox rules
- Isolate compromised endpoints
- Rotate exposed credentials/secrets
- Review privileged actions

Microsoft's current Defender guidance recommends resetting compromised credentials, revoking tokens, blocking identified malicious URLs/IPs, and investigating associated email artifacts. [8]

---

## 17. Immediate, Short-Term, and Long-Term Recommendations

The recommendations are divided according to the urgency model in the supplied Hunt.io template. [Template]

### 17.1 Immediate

- Investigate Entra **Attacker in the Middle** and **Anomalous Token** detections.
- Revoke active sessions/tokens for confirmed compromised accounts.
- Reset compromised credentials.
- Remove unauthorized inbox rules.
- Block validated phishing domains and URLs.
- Search for other users who received the same phishing campaign.
- Investigate mailbox and cloud-data access.
- Review privileged-account activity.

### 17.2 Short-Term

- Integrate email, URL-click, identity, endpoint, and cloud telemetry.
- Create an identity-centric AiTM analytic rule.
- Monitor new/unmanaged device authentication.
- Correlate suspicious URL clicks with subsequent authentication.
- Monitor inbox-rule creation following risky authentication.
- Establish privileged-user baselines.
- Create watchlists for known phishing infrastructure.
- Monitor OAuth application consent.

### 17.3 Long-Term

- Enforce **phishing-resistant MFA**.
- Deploy FIDO2/WebAuthn/passkey-based authentication where appropriate.
- Use Conditional Access authentication-strength policies.
- Implement token protection where supported.
- Deploy identity-centric UEBA.
- Establish recurring AiTM threat hunts.
- Improve SaaS audit-log coverage.
- Implement automated session/token revocation through SOAR.
- Maintain an identity attack-path and exposure-management program.

Microsoft's current Entra deployment guidance supports planning and enforcing phishing-resistant authentication through Conditional Access authentication-strength policies. [5]

---

## 18. Detection Engineering Backlog

| Priority | Detection | Data Required |
|---|---|---|
| **P1** | Entra AiTM risk detection correlation | Entra ID Protection |
| **P1** | Anomalous token + cloud activity | Entra + M365 |
| **P1** | Phishing click + suspicious login | Defender for Office 365 + Entra |
| **P1** | Suspicious session + inbox rule | Entra + CloudAppEvents |
| **P1** | Session replay | Identity/session telemetry |
| **P2** | New device + risky login | Entra |
| **P2** | Unmanaged device + privileged login | Entra/Intune |
| **P2** | Bulk cloud access after risky sign-in | M365/CloudAppEvents |
| **P3** | Suspicious domain infrastructure | DNS/Proxy/TI |
| **P3** | New OAuth application after risky login | Entra Audit Logs |

---

## 19. Intelligence Gaps → Engineering Backlog

| Intelligence Gap | Engineering Action |
|---|---|
| No phishing-click correlation | Integrate Defender for Office 365 URL telemetry |
| No session correlation | Ingest Entra linkable/session identifiers |
| No token-risk telemetry | Export Entra ID Protection logs |
| No device baseline | Integrate Intune/device identity |
| No SaaS visibility | Enable Unified Audit Log |
| No URL redirect visibility | Centralize proxy/web telemetry |
| Limited domain intelligence | Integrate CTI enrichment |
| No automated containment | Build SOAR token-revocation workflow |

---

## 20. Recommended Detection Architecture

```text
                    +----------------------+
                    |  Email / Phishing    |
                    |  Defender for O365   |
                    +----------+-----------+
                               |
                               v
                    +----------------------+
                    | URL / Click Telemetry |
                    +----------+-----------+
                               |
                               v
+----------------+    +----------------------+    +----------------+
| Entra ID        |--->| Microsoft Sentinel   |<---| Defender XDR   |
| Sign-in Logs    |    | / SIEM               |    | Endpoint       |
+----------------+    +----------+-----------+    +----------------+
                               |
                    +----------+-----------+
                    | Identity Correlation  |
                    | Session / Token IDs    |
                    +----------+-----------+
                               |
                               v
                    +----------------------+
                    | SaaS / Cloud Activity |
                    | M365 / Azure / AWS    |
                    +----------+-----------+
                               |
                               v
                    +----------------------+
                    | Risk Scoring / UEBA   |
                    +----------+-----------+
                               |
                               v
                    +----------------------+
                    | SOC Investigation     |
                    +----------+-----------+
                               |
                               v
                    +----------------------+
                    | SOAR / Containment    |
                    +----------------------+
```

---

## 21. Success Criteria

The hunt should be considered successful when the SOC can reliably answer:

- **Which users received the phishing campaign?**
- **Which users clicked the phishing infrastructure?**
- **Which users authenticated afterward?**
- **Which authentication sessions were suspicious?**
- **Was a token/session potentially stolen?**
- **Did the attacker replay the session?**
- **What cloud/SaaS resources were accessed?**
- **Did the attacker create persistence?**
- **Was data accessed or exfiltrated?**
- **Which other users or systems were exposed?**

---

## 22. Hunt Outcome

### Threat Assessment

**HIGH**

### Confidence

**High for threat relevance; low for actual compromise**

The current threat intelligence strongly supports the relevance of AiTM phishing as an active identity threat. However, this repository is a **simulated hunt** and does not contain real enterprise telemetry.

### Most Important Attack Chain

```text
Phishing
   |
   v
Credential Harvesting
   |
   v
AiTM Authentication Proxy
   |
   v
MFA Interception / Relay
   |
   v
Session / Token Theft
   |
   v
Session Replay
   |
   v
Cloud / SaaS Access
   |
   +---------> Mailbox Access
   |
   +---------> Inbox Rule
   |
   +---------> Internal Phishing
   |
   +---------> Data Collection
   |
   +---------> Financial Fraud
```

### Core Hunting Principle

> **Do not investigate the phishing email in isolation. Correlate the phishing event with identity, session/token, endpoint, mailbox, cloud, and data-access telemetry.**

---

## 23. Appendix — Example Timeline

```text
09:55  Phishing email delivered
10:01  User clicks suspicious URL
10:02  Redirect to staging infrastructure
10:03  User reaches AiTM authentication page
10:04  User completes authentication
10:04  Authentication succeeds
10:05  Identity risk generated
10:07  Session observed from unusual IP/device
10:09  Microsoft 365 mailbox accessed
10:11  New inbox rule created
10:15  SharePoint files accessed
10:18  Internal phishing email sent
10:20  SOC detection triggered
10:25  Session/token revoked
10:30  Account credentials reset
10:40  Inbox rule removed
10:45  Additional impacted users identified
```

---

## 24. Appendix — Example Investigation Checklist

### Email

- [ ] Sender verified
- [ ] Reply-to verified
- [ ] SPF checked
- [ ] DKIM checked
- [ ] DMARC checked
- [ ] URL extracted
- [ ] Redirect chain analyzed
- [ ] Domain reputation checked
- [ ] Campaign scope identified

### Identity

- [ ] User identified
- [ ] Privilege level checked
- [ ] Sign-in reviewed
- [ ] IP checked
- [ ] ASN checked
- [ ] Geography checked
- [ ] Device checked
- [ ] MFA checked
- [ ] Risk events reviewed
- [ ] Session identifiers correlated

### Cloud / SaaS

- [ ] Mailbox accessed
- [ ] Inbox rules reviewed
- [ ] Forwarding reviewed
- [ ] SharePoint activity reviewed
- [ ] OneDrive activity reviewed
- [ ] OAuth activity reviewed
- [ ] Administrative activity reviewed

### Endpoint

- [ ] Browser telemetry reviewed
- [ ] Suspicious process activity checked
- [ ] Malware/infostealer checked
- [ ] Device compliance checked
- [ ] Network connections checked

### Response

- [ ] Tokens revoked
- [ ] Password reset
- [ ] MFA methods reviewed
- [ ] Malicious rules removed
- [ ] URLs/domains blocked
- [ ] Endpoint isolated if required
- [ ] Additional users searched
- [ ] Detection created/tuned

---

## 25. References and External Sources

The supplied Hunt.io template recommends that external references be trusted, primary, and directly related to the investigation. [Template]

### Microsoft

1. **Microsoft Security — Breaking the code: Multi-stage 'code of conduct' phishing campaign leads to AiTM token compromise (May 2026)**  
   https://www.microsoft.com/en-us/security/blog/2026/05/04/breaking-the-code-multi-stage-code-of-conduct-phishing-campaign-leads-to-aitm-token-compromise/

2. **Microsoft Security — Inside Tycoon2FA: How a leading AiTM phishing kit operated at scale (March 2026)**  
   https://www.microsoft.com/en-us/security/blog/2026/03/04/inside-tycoon2fa-how-a-leading-aitm-phishing-kit-operated-at-scale/

3. **Microsoft Security — Email threat landscape: Q1 2026 trends and insights (April 2026)**  
   https://www.microsoft.com/en-us/security/blog/2026/04/30/email-threat-landscape-q1-2026-trends-and-insights/

4. **Microsoft Learn — Understanding Tokens in Microsoft Entra ID**  
   https://learn.microsoft.com/en-us/entra/identity/devices/concept-tokens-microsoft-entra-id

5. **Microsoft Learn — Protecting Tokens in Microsoft Entra ID**  
   https://learn.microsoft.com/en-us/entra/identity/devices/protecting-tokens-microsoft-entra-id

6. **Microsoft Learn — Track and investigate identity activities with linkable identifiers in Microsoft Entra**  
   https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-authentication-track-linkable-identifiers

7. **Microsoft Learn — Session Cookie Theft Alert Grading / Investigation**  
   https://learn.microsoft.com/en-us/defender-xdr/session-cookie-theft-alert

8. **Microsoft Community / Entra — Defeating Adversary-in-the-Middle phishing attacks**  
   https://techcommunity.microsoft.com/blog/microsoft-entra-blog/defeating-adversary-in-the-middle-phishing-attacks/1751777

### MITRE ATT&CK

9. **T1557 — Adversary-in-the-Middle**  
   https://attack.mitre.org/techniques/T1557/

10. **T1539 — Steal Web Session Cookie**  
    https://attack.mitre.org/techniques/T1539/

11. **T1566 — Phishing**  
    https://attack.mitre.org/techniques/T1566/

12. **T1566.002 — Phishing: Spearphishing Link**  
    https://attack.mitre.org/techniques/T1566/002/

13. **T1598.003 — Phishing for Information: Spearphishing Link**  
    https://attack.mitre.org/techniques/T1598/003/

14. **T1111 — Multi-Factor Authentication Interception**  
    https://attack.mitre.org/techniques/T1111/

15. **T1528 — Steal Application Access Token**  
    https://attack.mitre.org/techniques/T1528/

16. **T1114 — Email Collection**  
    https://attack.mitre.org/techniques/T1114/

17. **T1530 — Data from Cloud Storage**  
    https://attack.mitre.org/techniques/T1530/

18. **MITRE ATT&CK — Evilginx2 (S9003)**  
    https://attack.mitre.org/software/S9003/

### Other

19. **Cloudflare — Phishing-resistant MFA**  
    https://www.cloudflare.com/sase/use-cases/phishing-resistant-mfa/

---

## 26. Repository Structure

```text
adversary-in-the-middle-phishing/
│
├── README.md
│
├── report/
│   └── aitm-threat-hunting-report.md
│
├── queries/
│   ├── sentinel/
│   │   ├── suspicious_signins.kql
│   │   ├── unmanaged_device_signins.kql
│   │   ├── mfa_changes.kql
│   │   ├── inbox_rules.kql
│   │   ├── oauth_changes.kql
│   │   └── session_replay.kql
│   │
│   ├── defender/
│   │   └── aitm_advanced_hunting.kql
│   │
│   └── splunk/
│       └── aitm_hunting.spl
│
├── detections/
│   ├── aitm_identity_risk.yaml
│   ├── session_replay.yaml
│   └── phishing_auth_correlation.yaml
│
├── mitre/
│   └── attack-mapping.md
│
├── playbooks/
│   └── aitm-incident-response.md
│
├── intelligence/
│   ├── threat-intelligence.md
│   └── indicators.csv
│
├── screenshots/
│   └── README.md
│
└── LICENSE
```

---

## 27. Future Enhancements

This project can be expanded into a complete **SOC L2/L3 threat-hunting portfolio project**:

- [ ] Add realistic phishing-email samples
- [ ] Add sanitized Entra sign-in logs
- [ ] Add Microsoft Defender Advanced Hunting queries
- [ ] Add 15+ production-quality KQL hunts
- [ ] Add Splunk SPL equivalents
- [ ] Add Sigma detections
- [ ] Add MITRE ATT&CK Navigator layer
- [ ] Add simulated AiTM attack timeline
- [ ] Add URL/domain enrichment workflow
- [ ] Add session/token correlation queries
- [ ] Add mailbox compromise detections
- [ ] Add OAuth abuse detections
- [ ] Add Microsoft Sentinel analytic rules
- [ ] Add Sentinel Workbook
- [ ] Add SOAR playbook for token revocation
- [ ] Add automated phishing URL blocking
- [ ] Add automated compromised-user containment
- [ ] Add detection validation using Atomic Red Team or a controlled lab
- [ ] Add screenshots and investigation evidence

---

## 28. Disclaimer

This repository is intended for:

- Defensive security
- Threat hunting
- Detection engineering
- Security operations training
- Incident-response preparation
- Cybersecurity portfolio development

The findings in this report are **simulated** unless explicitly stated otherwise.

The KQL queries are starting points and must be validated against the actual Microsoft Sentinel/Defender schema and telemetry available in the target environment.

Do not conduct phishing, credential interception, session theft, or other security testing against systems or users without explicit authorization.

---

## 29. Sensitivity Label

**INTERNAL**

This report contains:

- Threat-hunting methodology
- Detection logic
- Identity attack scenarios
- Cloud/SaaS investigation techniques
- Security telemetry requirements
- Potential detection gaps

The classification follows the supplied Hunt.io template's sensitivity categories:

- Public
- Internal
- Confidential
- Restricted

---

## 30. Project Outcome

This project demonstrates the complete threat-hunting lifecycle:

```text
Threat Intelligence
        ↓
Threat Hypothesis
        ↓
Phishing Investigation
        ↓
Identity Analysis
        ↓
Session / Token Correlation
        ↓
Cloud / SaaS Investigation
        ↓
MITRE ATT&CK Mapping
        ↓
Detection Engineering
        ↓
Incident Response
        ↓
SOAR Automation
```

### Core Analyst Takeaway

> **AiTM phishing should not be investigated as an email-only threat. The most valuable hunting signal appears when phishing telemetry is correlated with authentication, session/token, device, mailbox, cloud, and data-access activity.**

---

## Author

**SOC Analyst / Threat Hunter**

**Focus Areas:**

- Threat Hunting
- Security Operations
- Incident Response
- Microsoft Sentinel
- Microsoft Defender XDR
- Microsoft Entra ID
- Identity Security
- Cloud Security
- MITRE ATT&CK
- Detection Engineering
- SOAR Automation
