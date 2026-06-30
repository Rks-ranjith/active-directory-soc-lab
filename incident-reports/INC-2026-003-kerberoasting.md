# Incident Report — INC-2026-003

| Field | Value |
|---|---|
| Incident ID | INC-2026-003 |
| Date | June 30, 2026 |
| Analyst | [Your Name] |
| Severity | High |
| Status | Closed — simulated lab exercise |

---

## Executive Summary

At approximately 12:46 IST, Wazuh generated a series of high-severity alerts corresponding to RC4-encrypted Kerberos Service Ticket (TGS) requests targeting the `svc-backup` service account on the `corp.local` domain. Investigation confirmed that this was a Kerberoasting attempt originating from the attacker VM `192.168.100.50` (Kali Linux), utilizing credentials belonging to the domain account `bob.finance`. 

Forensic analysis revealed a total of 4 successive TGS requests between 12:00:21 and 12:46:26 IST. This activity was preceded by active network reconnaissance (Nmap port scanning) and an SMB password spray attempt against the Domain Controller from the same source IP.

---

## Timeline

| Time (IST) | Event | Source IP | Description |
|---|---|---|---|
| 11:50:00 | Nmap service scan detected against `DC01` | `192.168.100.50` | Active fingerprinting of AD services (ports 88, 389, 445). |
| 11:55:00 | Logon failure sequence initiated | `192.168.100.50` | Repeated Event ID 4625 generated against `administrator` account. |
| 12:00:21 | TGS Request #1 (`Event ID 4769`) | `192.168.100.50` | TGS requested for `svc-backup` using `0x17` (RC4-HMAC) by user `bob.finance`. |
| 12:07:35 | TGS Request #2 (`Event ID 4769`) | `192.168.100.50` | Duplicate TGS request for `svc-backup` (harvesting hash). |
| 12:12:46 | TGS Request #3 (`Event ID 4769`) | `192.168.100.50` | Duplicate TGS request for `svc-backup`. |
| 12:46:26 | TGS Request #4 (`Event ID 4769`) | `192.168.100.50` | Final TGS request for `svc-backup`. |
| 12:47:00 | Alert Triage & Response | — | Analyst triages Wazuh alert series; confirms `bob.finance` lacks business justification to access backup services. |

---

## Evidence

- **Wazuh Security Alerts:** Custom Rule `4f8e0d3a` (Kerberoasting via RC4) fired for `Event ID 4769`.
- **SIEM Validation Query:**
  ```spl
  index=wineventlog EventCode=4769 TicketEncryptionType=0x17
  | table _time, Account_Name, Service_Name, Client_Address, TicketEncryptionType
  ```
- **Raw Telemetry Fields:**
  - `EventID=4769`
  - `TargetUserName=bob.finance`
  - `ServiceName=svc-backup`
  - `TicketEncryptionType=0x17` (RC4-HMAC)
  - `IpAddress=192.168.100.50` (or loopback `::1` depending on domain routing)

---

## Root Cause

The service account `svc-backup` was configured with an Active Directory Service Principal Name (SPN) `HTTP/backup.corp.local` and assigned a weak/legacy static password. Additionally, the domain configuration permitted Kerberos ticket requests using legacy `RC4-HMAC` (`0x17`) encryption. 

Any domain-authenticated account (e.g., `bob.finance`) can request a service ticket for any SPN, which is encrypted with the service account's password hash. The attacker harvested these tickets to attempt offline brute-force cracking.

---

## Impact Assessment

No domain compromise or privilege escalation occurred during this incident as the attack was terminated post-extraction. In a production environment, if the offline cracking of the `svc-backup` NTLM hash succeeded, the attacker would obtain the plaintext password. Depending on the privileges assigned to `svc-backup` (e.g., local administrator on backup servers, network share access), this could lead to lateral movement and full domain compromise.

---

## Recommendations

1. **Enforce AES-Only Kerberos Encryption:** Set the Active Directory attribute `msDS-SupportedEncryptionTypes` to `0x18` (AES256) and `0x8` (AES128) on all service accounts, eliminating the RC4 downgrade path.
2. **Deploy Group Managed Service Accounts (gMSA):** Migrate `svc-backup` to a gMSA. This automates password rotation and enforces strong, 240-character passwords, rendering offline cracking attacks impossible.
3. **Password Complexity & Rotation:** If gMSA is not viable, immediately reset the `svc-backup` password to a 25+ character random string and configure a 90-day rotation cycle.
4. **Permanent SIEM Detections:** Retain the custom Sigma rule (`detection-rules/kerberoasting.yml`) in active SIEM rulesets.
5. **Account Auditing:** Audit the compromised host and user account (`bob.finance`) to identify initial access vectors and verify no other malicious actions were taken prior to the Kerberoasting activity.
