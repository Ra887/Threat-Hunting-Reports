# Threat Hunt Report: Detection of Identity-Based Attacks Through Valid Account and Cloud Identity Abuse


## 1. Purpose of the Hunt

The purpose of this proactive hunt is to identify adversaries abusing **legitimate user, administrator, service, and cloud credentials** to gain access to enterprise resources while avoiding traditional malware-based detection.

Identity-based attacks are particularly important because a compromised account can provide an attacker with legitimate access to VPNs, SaaS applications, cloud consoles, email, and internal systems. MITRE ATT&CK classifies this behavior under **T1078 — Valid Accounts**, which can support Initial Access, Persistence, Privilege Escalation, and Defense Evasion.

The cloud-specific sub-technique **T1078.004 — Valid Accounts**: Cloud Accounts was updated by MITRE in May 2026 and explicitly covers abuse of cloud identities, service accounts, federated accounts, privileged accounts, and additional cloud credentials.


### Threat Intelligence Trigger

The hunt is driven by several current threat trends:
- CrowdStrike's 2026 Financial Services Threat Landscape reports that hands-on-keyboard intrusions against financial institutions increased **43% globally over two years**, with adversaries increasingly exploiting trusted identities and SaaS applications.
- CrowdStrike identifies financial services as the fourth most targeted sector globally, representing 12% of observed activity in its reporting period.
- MITRE's current T1078.004 detection guidance specifically recommends looking for impossible geolocation, unusual API activity, abnormal cloud-productivity usage, and deviations from normal SaaS user profiles.
- Microsoft reported approximately 8.3 billion email-based phishing threats in Q1 2026, with QR-code phishing more than doubling during the quarter.
- Microsoft also documented OAuth abuse in 2026, where attackers exploited legitimate OAuth functionality for phishing and redirection, demonstrating that identity attacks can abuse legitimate authentication infrastructure rather than simply steal passwords.


### Hunt Scope

The hunt focuses on:

**Identity**

- Authentication
- MFA
- OAuth
- Tokens
- Privileged accounts
- Service principals
- SaaS access

**Endpoint**

- Windows logons
- Browser activity
- Credential access
- PowerShell
- Remote services

**Cloud**

- Entra ID
- Azure Activity
- AWS IAM/CloudTrail
- SaaS audit logs

**Email**

- Phishing
- BEC
- Suspicious authentication following phishing

### Key Findings Summary

For this simulated hunt, the following suspicious behaviors were identified as hunt findings to validate in a real environment:

| Finding	| Description |	Severity |
| :--- | :---: | ---: |
| F-001	| Successful authentication from anomalous geographic location	| High |
| F-002	| Privileged account accessed from previously unseen device	| Critical |
| F-003	| New OAuth application granted high-risk permissions |	Critical |
| F-004	| New MFA method registered shortly after suspicious login	| Critical |
| F-005	| Unusual cloud API activity following account authentication	| High |
| F-006	| Abnormal SaaS data access/download activity	| High |
| F-007	| Legacy authentication attempt against privileged account	| High |

**Overall assessment: High risk.**

The most concerning scenario is a sequence involving:

**Compromised credentials → anomalous login → MFA manipulation → OAuth persistence → cloud/SaaS access → sensitive-data access**

## 2. Hunt Details

### Target Environment

Primary: 
- Microsoft Entra ID
- Microsoft 365
- Azure
- Windows endpoints
- Microsoft Defender
- Microsoft Sentinel

Optional: 
- Okta
- AWS
- Google Workspace
- CrowdStrike Falcon
- Splunk

### Data Sources

| Data Source |	Purpose |
| :--- | :--- |
| Entra Sign-in Logs	| Authentication analysis| 
| Entra Audit Logs	| Account/MFA/application changes |
| Unified Audit Log |	M365/SaaS activity |
| Defender for Endpoint	| Endpoint behavior |
| Azure Activity Logs	| Cloud administration |
| CloudTrail	| AWS identity/API activity |
| VPN Logs	| Remote authentication |
| Proxy Logs	| Web activity |
| DNS Logs	| Suspicious infrastructure |
| EDR	| Credential/access behavior |
| Email Security	| Phishing correlation |


## 3. Hypothesis / Trigger

The supplied template recommends documenting whether a hunt was initiated by a hypothesis, new threat intelligence, anomalous activity or a previous incident.

**Primary Hypothesis**:

**An attacker may have obtained valid corporate credentials and be using legitimate authentication mechanisms to access enterprise, cloud, and SaaS resources while attempting to evade malware-based detection.**

**Secondary Hypotheses**:

- **H1 — Geographic anomaly**: A compromised account may be used from a location inconsistent with the user's normal activity.

- **H2 — Device anomaly**: A compromised account may authenticate from a previously unseen device or browser.

- **H3 — MFA manipulation**: An attacker may register or modify authentication methods after obtaining access.

- **H4 — OAuth persistence**: An attacker may grant a malicious or unauthorized OAuth application persistent access to corporate resources.

- **H5 — Cloud privilege escalation**: A compromised identity may perform cloud API operations outside its normal behavioral baseline.

- **H6 — Data access**: An attacker may use legitimate SaaS credentials to access and download sensitive organizational data.

## 4. Threat Intelligence Context

Why identity-based hunting is important

Traditional detection frequently asks:

"Did malware execute?"

Identity hunting asks a different question:

"Is this legitimate identity behaving legitimately?"

This distinction is increasingly important.

MITRE states that adversaries can use compromised credentials without malware or additional tools, making detection more difficult because the access itself may appear legitimate.

Cloud identities are particularly dangerous because compromised credentials may allow:

Initial access
Persistence
Privilege escalation
Cloud API access
SaaS access
Data theft
Lateral movement
Creation of additional credentials

MITRE specifically notes that attackers can create additional cloud credentials for persistence and potentially bypass MFA controls.

