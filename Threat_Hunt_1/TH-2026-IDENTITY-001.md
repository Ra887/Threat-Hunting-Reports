# Threat Hunt Report: Detection of Identity-Based Attacks Through Valid Account and Cloud Identity Abuse


## Purpose of the Hunt

The purpose of this proactive hunt is to identify adversaries abusing **legitimate user, administrator, service, and cloud credentials** to gain access to enterprise resources while avoiding traditional malware-based detection.

Identity-based attacks are particularly important because a compromised account can provide an attacker with legitimate access to VPNs, SaaS applications, cloud consoles, email, and internal systems. MITRE ATT&CK classifies this behavior under **T1078 — Valid Accounts**, which can support Initial Access, Persistence, Privilege Escalation, and Defense Evasion.

The cloud-specific sub-technique **T1078.004 — Valid Accounts**: Cloud Accounts was updated by MITRE in May 2026 and explicitly covers abuse of cloud identities, service accounts, federated accounts, privileged accounts, and additional cloud credentials.


## Threat Intelligence Trigger

The hunt is driven by several current threat trends:
- CrowdStrike's 2026 Financial Services Threat Landscape reports that hands-on-keyboard intrusions against financial institutions increased **43% globally over two years**, with adversaries increasingly exploiting trusted identities and SaaS applications.
- CrowdStrike identifies financial services as the fourth most targeted sector globally, representing 12% of observed activity in its reporting period.
- MITRE's current T1078.004 detection guidance specifically recommends looking for impossible geolocation, unusual API activity, abnormal cloud-productivity usage, and deviations from normal SaaS user profiles.
- Microsoft reported approximately 8.3 billion email-based phishing threats in Q1 2026, with QR-code phishing more than doubling during the quarter.
- Microsoft also documented OAuth abuse in 2026, where attackers exploited legitimate OAuth functionality for phishing and redirection, demonstrating that identity attacks can abuse legitimate authentication infrastructure rather than simply steal passwords.


## Hunt Scope

The hunt focuses on:

**Identity**

→ Authentication
→ MFA
→ OAuth
→ Tokens
→ Privileged accounts
→ Service principals
→ SaaS access

**Endpoint**

→ Windows logons
→ Browser activity
→ Credential access
→ PowerShell
→ Remote services

**Cloud**

→ Entra ID
→ Azure Activity
→ AWS IAM/CloudTrail
→ SaaS audit logs

**Email**

→ Phishing
→ BEC
→ Suspicious authentication following phishing

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

