# Threat Hunting: Identity-Based Attacks

![Threat Hunting](https://img.shields.io/badge/Project-Threat%20Hunting-blue)
![Focus](https://img.shields.io/badge/Focus-Identity%20Security-red)
![MITRE ATT%26CK](https://img.shields.io/badge/MITRE%20ATT%26CK-T1078-orange)
![Platform](https://img.shields.io/badge/Primary%20Platform-Microsoft%20Sentinel-blue)
![Status](https://img.shields.io/badge/Status-Simulated%20Hunt-yellow)

## 📌 Project Overview

This repository contains a **threat hunting report and detection methodology for identity-based attacks**, with a primary focus on the abuse of **valid accounts, cloud identities, SaaS access, OAuth applications, MFA mechanisms, and privileged identities**.

The project is designed from a **SOC L2/L3 threat-hunting perspective** and demonstrates how threat intelligence can be converted into:

- Threat-hunting hypotheses
- Behavioral analytics
- Identity and cloud investigations
- MITRE ATT&CK mappings
- Microsoft Sentinel KQL hunts
- Detection engineering opportunities
- Incident-response workflows
- SOAR automation opportunities

> **Important:** This is a simulated threat-hunting exercise. No real organizational compromise is claimed. The findings are example findings that should be validated against actual enterprise telemetry.

---

## 🎯 Objectives

The primary objectives of this hunt are to:

1. Identify potential abuse of **valid user and privileged accounts**.
2. Detect suspicious authentication from **new locations, IPs, devices, and ASNs**.
3. Identify potential **MFA manipulation** following account compromise.
4. Detect suspicious **OAuth application consent and service-principal activity**.
5. Identify abnormal **cloud API and IAM activity**.
6. Detect suspicious access to **SaaS and cloud-hosted data**.
7. Correlate identity, endpoint, cloud, email, and network telemetry.
8. Map observed behaviors to **MITRE ATT&CK**.
9. Convert hunting findings into actionable **detection rules**.
10. Identify telemetry and monitoring gaps that should be addressed by the security engineering team.

---

## 🏢 Target Industries

Identity-based attacks are relevant across almost every organization, but this hunt is particularly applicable to:

| Industry | Why It Matters |
|---|---|
| **Banking** | Privileged identities and high-value financial systems |
| **FinTech** | Cloud/SaaS-heavy environments and sensitive financial data |
| **Cryptocurrency / Web3** | Wallets, cloud credentials, developer accounts, and API keys |
| **SaaS** | Large-scale cloud identities and application access |
| **Technology** | Developer, CI/CD, GitHub, and cloud identities |
| **Healthcare** | Sensitive patient data and high ransomware impact |
| **Government** | Privileged identities and sensitive information |
| **Manufacturing** | Hybrid IT/OT environments and ransomware exposure |
| **Enterprise** | Large identity footprint and extensive SaaS usage |

---

## 🔎 Threat Hunting Hypothesis

### Primary Hypothesis

> **An attacker may have obtained valid corporate credentials and be using legitimate authentication mechanisms to access enterprise, cloud, and SaaS resources while attempting to evade malware-based detection.**

### Secondary Hypotheses

- A compromised account may authenticate from a location inconsistent with the user's normal behavior.
- A compromised identity may be used from a previously unseen device or browser.
- An attacker may register or modify an MFA method to establish persistence.
- An attacker may grant a malicious OAuth application access to corporate resources.
- A compromised cloud identity may perform API operations outside its normal behavioral baseline.
- An attacker may use legitimate SaaS credentials to access and download sensitive organizational data.

---

## 🧠 Why Identity-Based Threat Hunting?

Traditional security monitoring often focuses on questions such as:

```text
Did malware execute?
Did a malicious file execute?
Was a known IOC observed?
```

Identity-based threat hunting asks a different question:

```text
Is this legitimate identity behaving legitimately?
```

A compromised identity may allow an attacker to:

- Access corporate applications
- Access email
- Access cloud consoles
- Access SaaS applications
- Obtain additional credentials
- Modify authentication methods
- Grant OAuth permissions
- Escalate privileges
- Access sensitive data
- Perform lateral movement

This makes **identity telemetry a critical component of modern threat hunting**.

---

## 🗺️ Attack Chain

The primary attack chain investigated in this project is:

```text
Phishing / Credential Theft
        |
        v
Compromised Valid Account
        |
        v
Anomalous Authentication
        |
        v
MFA / Session Abuse
        |
        v
OAuth Persistence
        |
        v
Cloud Privilege Escalation
        |
        v
SaaS / Cloud Data Access
        |
        v
Potential Exfiltration
```

---

## 📊 Hunt Scope

### Identity

- User authentication
- Privileged accounts
- MFA changes
- OAuth consent
- Service principals
- Cloud identities
- Session/token activity

### Endpoint

- Windows logons
- Browser activity
- Credential access
- PowerShell
- Remote access tools
- Suspicious process execution

### Cloud

- Microsoft Entra ID
- Azure Activity Logs
- AWS CloudTrail
- IAM activity
- Service principals
- Cloud storage
- Key Vault/secrets access

### Email

- Phishing
- Business Email Compromise
- Suspicious links
- QR-code phishing
- Authentication activity following phishing

### SaaS

- Microsoft 365
- SharePoint
- OneDrive
- Teams
- Other enterprise SaaS platforms

---

## 🛠️ Data Sources

| Data Source | Purpose |
|---|---|
| **Microsoft Entra Sign-in Logs** | Authentication and login analysis |
| **Microsoft Entra Audit Logs** | Account, MFA, application, and directory changes |
| **Microsoft 365 Unified Audit Log** | SaaS and data-access activity |
| **Microsoft Defender for Endpoint** | Endpoint and process investigation |
| **Azure Activity Logs** | Cloud administrative activity |
| **AWS CloudTrail** | AWS identity and API activity |
| **VPN Logs** | Remote authentication correlation |
| **Proxy Logs** | Web activity |
| **DNS Logs** | Suspicious infrastructure and C2 analysis |
| **EDR Telemetry** | Endpoint behavior and credential-access investigation |
| **Email Security Logs** | Phishing and email-based attack correlation |

---

## 🚨 Simulated Hunt Findings

> These are **simulated findings for the purpose of the hunting exercise** and do not represent evidence of an actual compromise.

| ID | Finding | Target | MITRE ATT&CK | Severity |
|---|---|---|---|---|
| **F-001** | Login from anomalous geography | User account | T1078.004 | High |
| **F-002** | Privileged account accessed from a new device | Global Administrator | T1078.004 | Critical |
| **F-003** | New OAuth application with sensitive permissions | Microsoft 365 tenant | T1098.003 / T1528 | Critical |
| **F-004** | New MFA method registered after suspicious login | User account | T1098 | Critical |
| **F-005** | Unusual cloud API activity | Azure subscription | T1078.004 | High |
| **F-006** | Large SaaS data download | Microsoft 365 / SharePoint | T1530 | High |
| **F-007** | Legacy authentication attempt | Privileged account | T1078 | High |

---

## 🔬 Key Hunting Scenarios

### 1. Anomalous Authentication

Look for:

- New country
- New IP address
- New ASN
- Impossible travel
- Unusual authentication time
- New device
- New browser
- Unexpected authentication method

Example:

```text
Normal:
India → Corporate VPN → Managed Windows Device

Observed:
New Country → New ASN → Unmanaged Browser → Successful Login
```

---

### 2. Privileged Account from New Device

Privileged identities should have predictable access patterns.

Hunt for:

```text
Privileged Account
        +
Previously Unseen Device
        +
Successful Authentication
```

Increase severity when combined with:

```text
New Location
+
New IP
+
MFA Change
+
Administrative Activity
```

---

### 3. OAuth Application Abuse

Look for:

- New OAuth applications
- User consent
- Admin consent
- High-risk permissions
- Rare applications
- Untrusted publishers
- New service principals
- OAuth consent followed by data access

Example high-risk permissions:

```text
Mail.Read
Mail.ReadWrite
Files.Read
Files.ReadWrite
offline_access
Directory.ReadWrite
```

Correlation:

```text
New OAuth Application
        +
Sensitive Permission
        +
Rare Application
        +
Unusual User/IP
        +
Mailbox/File Access
```

---

### 4. MFA Manipulation

Hunt for:

- New authenticator registration
- New phone number
- New FIDO/security key
- MFA method deletion
- Password reset
- Recovery-information modification

High-risk sequence:

```text
Suspicious Login
      |
      v
MFA Method Added
      |
      v
New Session
      |
      v
Privileged Action
```

---

### 5. Cloud API Abuse

Look for:

- IAM policy modification
- Role assignment
- Service-principal creation
- Access-key creation
- Storage enumeration
- Secret access
- Key Vault access
- Security-control modification
- Logging modification

Example:

```text
Normal User:
Microsoft Graph
SharePoint
Outlook

Observed:
Microsoft Graph
Azure Key Vault
IAM
Storage
Security Configuration
```

---

### 6. SaaS Data Access

Hunt for:

- Mass SharePoint downloads
- OneDrive downloads
- External sharing
- Large mailbox exports
- Bulk file access
- New external collaboration
- Unusual Teams/Slack access

Example:

```text
Normal:
10–30 files/day

Observed:
1,800 files
+
New IP
+
New Device
```

---

### 7. Legacy Authentication

Look for:

- IMAP
- POP
- SMTP AUTH
- Legacy Exchange protocols
- Other authentication flows that do not enforce modern authentication controls

Particular attention should be given to legacy authentication involving privileged accounts.

---

## 🧬 MITRE ATT&CK Mapping

| Tactic | Technique | ID | Hunting Application |
|---|---|---|---|
| **Initial Access** | Valid Accounts | **T1078** | Stolen credentials |
| **Initial Access** | Valid Accounts: Cloud Accounts | **T1078.004** | Entra/AWS/GCP accounts |
| **Persistence** | Account Manipulation | **T1098** | MFA/account changes |
| **Persistence** | Additional Cloud Roles | **T1098.003** | Cloud privilege |
| **Credential Access** | Steal Web Session Cookie | **T1539** | Session theft |
| **Credential Access** | Credentials from Web Browsers | **T1555.003** | Infostealer activity |
| **Credential Access** | Steal Application Access Token | **T1528** | OAuth/token abuse |
| **Collection** | Data from Cloud Storage | **T1530** | Cloud/SaaS collection |
| **Discovery** | Account Discovery | **T1087** | Identity reconnaissance |
| **Defense Evasion** | Valid Accounts | **T1078** | Legitimate access |
| **Privilege Escalation** | Valid Accounts | **T1078** | Privileged credential abuse |

---

## 💻 Microsoft Sentinel KQL

### Hunt 1 — Unusual Sign-ins

```kusto
SigninLogs
| where TimeGenerated > ago(30d)
| summarize
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    IPs = make_set(IPAddress, 20),
    Countries = make_set(LocationDetails.countryOrRegion, 20),
    Devices = make_set(DeviceDetail.displayName, 20)
    by UserPrincipalName
| where array_length(Countries) > 2
```

> **Note:** Geographic anomalies require tuning for corporate VPNs, proxies, travel, and known egress locations.

---

### Hunt 2 — Privileged Users

```kusto
SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType == 0
| where UserPrincipalName has_any (
    "admin",
    "administrator",
    "globaladmin"
)
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    Location,
    AppDisplayName,
    DeviceDetail,
    AuthenticationRequirement
| order by TimeGenerated desc
```

> **Production recommendation:** Replace username string matching with an authoritative privileged-user watchlist or identity group.

---

### Hunt 3 — MFA / Authentication Method Changes

```kusto
AuditLogs
| where TimeGenerated > ago(30d)
| where ActivityDisplayName has_any (
    "authentication method",
    "MFA",
    "authentication"
)
| project
    TimeGenerated,
    InitiatedBy,
    ActivityDisplayName,
    TargetResources,
    Result
| order by TimeGenerated desc
```

---

### Hunt 4 — OAuth / Application Changes

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

---

## 🧮 Identity Compromise Risk Scoring

A practical identity risk model can correlate multiple weak signals instead of generating alerts from a single event.

| Behavior | Score |
|---|---:|
| New country | +20 |
| New device | +20 |
| New ASN | +10 |
| Impossible travel | +30 |
| MFA change | +30 |
| OAuth consent | +30 |
| Privileged role change | +40 |
| Bulk download | +30 |
| Cloud IAM modification | +40 |
| Legacy authentication | +20 |

### Risk Classification

```text
0–29     → Low
30–59    → Medium
60–89    → High
90+      → Critical
```

### Example

```text
New Country       +20
New Device        +20
MFA Change        +30
OAuth Consent     +30
----------------------
Total             100
```

**Risk Level: CRITICAL**

---

## 🔗 High-Confidence Correlation

A mature identity hunt should correlate multiple telemetry sources.

```text
Identity Anomaly
        +
Endpoint Anomaly
        +
Cloud Anomaly
        +
SaaS/Data Anomaly
        =
High-Confidence Investigation
```

Example:

```text
New Country
      +
New Device
      +
MFA Registration
      +
OAuth Consent
      +
Bulk SharePoint Download
```

This sequence is significantly more suspicious than any individual event.

---

## 🕵️ Investigation Workflow

When suspicious identity activity is identified:

### Step 1 — Validate the Identity

Determine whether the account is:

- Employee
- Contractor
- Service account
- Privileged account
- Dormant account

### Step 2 — Validate Authentication

Review:

- Source IP
- ASN
- Geography
- Device
- Browser
- MFA
- Authentication method

### Step 3 — Check Persistence

Investigate:

- MFA changes
- Password changes
- OAuth applications
- Service principals
- API keys
- Access keys
- Additional roles

### Step 4 — Investigate the Endpoint

Search EDR for:

- Credential theft
- Browser credential access
- Infostealers
- PowerShell
- Suspicious downloads
- Remote-management tools

### Step 5 — Investigate Cloud Activity

Review:

- IAM
- Azure Activity Logs
- AWS CloudTrail
- Key Vault
- Storage
- Secrets
- Administrative operations

### Step 6 — Investigate Data Access

Identify:

- Files accessed
- Mailbox access
- SharePoint downloads
- External sharing
- Database access

### Step 7 — Containment

Depending on confidence:

- Revoke active sessions
- Reset credentials
- Revoke OAuth grants
- Remove unauthorized MFA methods
- Disable compromised accounts
- Disable malicious service principals
- Rotate API keys
- Isolate compromised endpoints

---

## 🚨 Detection Engineering Opportunities

### Detection 1 — Privileged Account + New Device

```text
IF
    User is Privileged
AND
    Device is Previously Unseen
AND
    Authentication Succeeds
THEN
    Generate High-Severity Alert
```

### Detection 2 — Suspicious Authentication + MFA Change

```text
Successful Login
      +
New MFA Method
      +
New Device/IP
```

**Severity: Critical**

### Detection 3 — OAuth Persistence

```text
New OAuth Consent
      +
Sensitive Permissions
      +
Rare Application
```

**Severity: High/Critical**

### Detection 4 — Identity + Data Access

```text
Anomalous Authentication
      +
New Device
      +
Bulk SaaS Download
```

**Severity: Critical**

### Detection 5 — Identity + Cloud Privilege

```text
Anomalous Login
      +
IAM Modification
      +
New Privileged Role
```

**Severity: Critical**

---

## 🧩 Intelligence Gaps

| Gap | Impact | Priority |
|---|---|---|
| No centralized identity baseline | Difficult to identify abnormal behavior | High |
| Incomplete SaaS audit logs | Limited data-access visibility | High |
| Missing VPN correlation | Difficult to validate travel anomalies | High |
| Limited OAuth monitoring | Persistence may go undetected | Critical |
| Incomplete endpoint coverage | Identity cannot be reliably associated with devices | High |
| Missing AWS/GCP identity telemetry | Cloud visibility gap | High |
| Limited MFA-change monitoring | Account-takeover persistence may be missed | Critical |
| No privileged-user baseline | Increased false positives | Medium |

---

## 🏗️ Recommended Telemetry Architecture

```text
             +------------------+
             |   Entra ID       |
             +------------------+
                      |
             +------------------+
             |     Okta         |
             +------------------+
                      |
             +------------------+
             | AWS / Azure / GCP |
             +------------------+
                      |
             +------------------+
             | SaaS Applications |
             +------------------+
                      |
             +------------------+
             | VPN / Email / EDR |
             +------------------+
                      |
                      v
             +------------------+
             |       SIEM       |
             | Microsoft Sentinel|
             +------------------+
                      |
                      v
             +------------------+
             | Identity Baseline |
             | UEBA / Analytics  |
             +------------------+
                      |
                      v
             +------------------+
             | SOC Investigation |
             +------------------+
                      |
                      v
             +------------------+
             | SOAR / Response   |
             +------------------+
```

---

## 📋 Recommendations

### Immediate

- Investigate anomalous privileged-account activity.
- Revoke suspicious sessions.
- Remove unauthorized MFA methods.
- Revoke suspicious OAuth applications.
- Disable compromised accounts when compromise is confirmed.
- Rotate exposed credentials and API keys.
- Review cloud administrative activity.

### Short-Term

- Create dedicated identity threat-hunting detections.
- Baseline user/device/IP relationships.
- Monitor privileged accounts separately.
- Alert on new OAuth applications.
- Alert on MFA registration changes.
- Integrate identity, endpoint, and cloud telemetry.
- Create high-risk identity watchlists.

### Long-Term

- Deploy identity-centric UEBA.
- Enforce phishing-resistant MFA.
- Reduce standing administrative privileges.
- Implement Privileged Identity Management.
- Eliminate legacy authentication.
- Implement continuous access evaluation where supported.
- Establish recurring identity threat hunts.
- Monitor service principals and workload identities.
- Develop automated SOAR response.

---

## 📈 Suggested Future Enhancements

This repository can be expanded into a complete **SOC L2/L3 threat-hunting portfolio** by adding:

- [ ] Realistic Entra ID sample logs
- [ ] Microsoft Defender telemetry
- [ ] Microsoft Sentinel analytics rules
- [ ] 10–15 production-quality KQL hunts
- [ ] Splunk SPL equivalents
- [ ] CrowdStrike/Falcon hunting queries
- [ ] YARA-L queries where applicable
- [ ] Sigma detection rules
- [ ] MITRE ATT&CK Navigator layer
- [ ] Attack timeline
- [ ] Investigation screenshots
- [ ] Sentinel Workbooks
- [ ] SOAR playbook
- [ ] Automated session revocation
- [ ] OAuth application containment workflow
- [ ] Identity risk scoring implementation

---

## 📁 Suggested Repository Structure

```text
identity-based-threat-hunting/
│
├── README.md
│
├── report/
│   └── identity-based-attacks-threat-hunting-report.md
│
├── queries/
│   ├── sentinel/
│   │   ├── unusual_signins.kql
│   │   ├── privileged_new_device.kql
│   │   ├── mfa_changes.kql
│   │   └── oauth_application_changes.kql
│   │
│   ├── splunk/
│   │   └── README.md
│   │
│   └── crowdstrike/
│       └── README.md
│
├── detections/
│   ├── identity_anomaly.yaml
│   ├── oauth_abuse.yaml
│   └── privileged_account_anomaly.yaml
│
├── mitre/
│   └── attack-mapping.md
│
├── playbooks/
│   └── identity-compromise-response.md
│
├── intelligence/
│   └── threat-intelligence.md
│
├── screenshots/
│   └── README.md
│
└── LICENSE
```

---

## 📚 MITRE ATT&CK References

- [T1078 — Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- [T1078.004 — Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)
- [T1098 — Account Manipulation](https://attack.mitre.org/techniques/T1098/)
- [T1098.003 — Additional Cloud Roles](https://attack.mitre.org/techniques/T1098/003/)
- [T1528 — Steal Application Access Token](https://attack.mitre.org/techniques/T1528/)
- [T1539 — Steal Web Session Cookie](https://attack.mitre.org/techniques/T1539/)
- [T1555.003 — Credentials from Web Browsers](https://attack.mitre.org/techniques/T1555/003/)
- [T1530 — Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)
- [DET0546 — Compromised Cloud Accounts](https://attack.mitre.org/detectionstrategies/DET0546/)

---

## 📰 Threat Intelligence Sources

The hunt was informed by current public threat intelligence and vendor research, including:

- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [CISA Cybersecurity Advisories](https://www.cisa.gov/news-events/cybersecurity-advisories)
- [Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/)
- [Microsoft Threat Intelligence](https://www.microsoft.com/en-us/security/blog/topic/threat-intelligence/)
- [CrowdStrike Global Threat Report](https://www.crowdstrike.com/en-us/global-threat-report/)
- [CrowdStrike Financial Services Threat Landscape](https://www.crowdstrike.com/en-us/resources/reports/crowdstrike-2026-financial-services-threat-landscape-report/)
- [Google Cloud Threat Horizons](https://cloud.google.com/security/report/resources/cloud-threat-horizons-report-h1-2026)
- [Palo Alto Networks Unit 42](https://unit42.paloaltonetworks.com/)

---

## ⚠️ Disclaimer

This repository is intended for **educational, defensive-security, threat-hunting, detection-engineering, and portfolio purposes**.

The reported findings are **simulated** unless explicitly identified as evidence from a real environment.

Do not execute offensive actions against systems that you do not own or have explicit authorization to test.

KQL queries are provided as **starting points** and should be validated, tuned, and tested against the organization's actual schema, logging configuration, VPN architecture, identity provider, and baseline behavior before being deployed as production detections.

---

## 🔐 Classification

**Internal**

This project contains threat-hunting methodology, detection logic, identity attack scenarios, and security telemetry requirements.

---

## 👤 Author

**SOC Analyst / Threat Hunter**

**Focus Areas:**

- Security Operations
- Threat Hunting
- Incident Response
- Microsoft Sentinel
- Microsoft Defender
- Cloud Security
- Identity Security
- MITRE ATT&CK
- Detection Engineering
- SOAR Automation

---

## ⭐ Project Outcome

This project demonstrates the ability to move from:

```text
Threat Intelligence
        ↓
Threat Hypothesis
        ↓
Data Collection
        ↓
Behavioral Analysis
        ↓
Threat Hunting
        ↓
MITRE ATT&CK Mapping
        ↓
Detection Engineering
        ↓
Incident Response
        ↓
SOAR Automation
```

The central objective is to demonstrate that modern threat hunting should not focus exclusively on **malware and static IOCs**, but also on detecting **legitimate identities performing illegitimate actions**.

---

## 📄 Primary Report

For the complete investigation methodology, findings, intelligence gaps, MITRE ATT&CK mapping, detection opportunities, recommendations, and investigation workflow, see:

`report/identity-based-attacks-threat-hunting-report.md`
