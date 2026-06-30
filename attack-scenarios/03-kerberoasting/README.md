# Attack Scenario 3 — Kerberoasting (Active Directory Credential Access)

**MITRE ATT&CK:** T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting  
**Date:** June 30, 2026  
**Source:** Kali Linux (`192.168.100.50`), authenticated as low-privilege domain user `bob.finance`  
**Target:** `svc-backup` service account, via Domain Controller `DC01` (`192.168.100.10`)

---

## Objective

Kerberoasting is a common credential access technique that targets Service Principal Name (SPN) accounts in Active Directory. Because any authenticated domain user can request a Kerberos service ticket (TGS-REQ) for any service account in the forest, attackers can request these tickets and attempt offline brute-force cracking of the service account’s password hash.

Since the ticket is encrypted using the service account's NTLM hash, a successful offline crack yields the plaintext password of the service account. The entire request occurs within legitimate Kerberos communication channels, making it invisible to traditional failed logon counters (Event ID 4625).

In this lab, the service account `svc-backup` was configured with a static password and an SPN (`HTTP/backup.corp.local`) to serve as a target.

---

## Phase 1: Attack Execution (Kali Linux)

### 1. Initial Attempt & Clock Skew Troubleshooting

Running `impacket-GetUserSPNs` against the Domain Controller from the Kali machine initially failed with a Kerberos clock skew error:

```bash
impacket-GetUserSPNs corp.local/bob.finance:Winter2025! -dc-ip 192.168.100.10 -request -outputfile kerberoast.hashes
```

**Error Encountered:**
`[-] Kerberos Session Error: KRB_AP_ERR_SKEW(Clock skew too great)`

**Root Cause:**
Kerberos relies heavily on timestamps to prevent replay attacks. By default, Active Directory permits a maximum time difference (clock skew) of **5 minutes** between the client and the Domain Controller. The Kali VM's clock was out of sync with `DC01`.

**Resolution:**
The system clock on the Kali host was manually synced to match the Domain Controller's UTC time:

```bash
# Set timezone to UTC
sudo timedatectl set-timezone UTC

# Manually sync date and time to match DC01
sudo date -u -s "2026-06-30 19:48:33"
```

---

### 2. Successful Ticket Harvesting

Once the clocks were aligned within the acceptable threshold, the command was executed again successfully:

```bash
impacket-GetUserSPNs corp.local/bob.finance:Winter2025! -dc-ip 192.168.100.10 -request -outputfile kerberoast.hashes
```

The tool successfully enumerated SPNs, identified `HTTP/backup.corp.local` mapped to `svc-backup`, requested the ticket, and saved the hash file.

Below is the screenshot showing the clock skew troubleshooting, successful ticket harvesting, hash extraction, and `cat` output of the raw hash:

![Impacket Kerberoasting Execution and Hash Output](../../images/kali-kerberoasting-success.png)

---

### 3. Multiple Ticket Requests

To simulate persistent harvesting or multiple extraction attempts, additional runs were performed to request tickets into separate hash files:

```bash
impacket-GetUserSPNs corp.local/bob.finance:Winter2025! -dc-ip 192.168.100.10 -request -outputfile kerberoast2.hashes
impacket-GetUserSPNs corp.local/bob.finance:Winter2025! -dc-ip 192.168.100.10 -request -outputfile kerberoast3.hashes
impacket-GetUserSPNs corp.local/bob.finance:Winter2025! -dc-ip 192.168.100.10 -request -outputfile kerberoast4.hashes
```

![Multiple Kerberos Ticket Requests](../../images/kali-kerberoasting-multiple.png)

---

## Phase 2: Telemetry & Detection (Wazuh SIEM)

### 1. Ingestion of Event ID 4769

The Domain Controller logged each TGS request as Windows Security **Event ID 4769 (A Kerberos service ticket was requested)**. These logs were forwarded to Wazuh via Sysmon/Event Log channels.

Filtering the Wazuh Dashboard by `data.win.system.eventID: 4769` displays a clear record of the activity:

![Wazuh Events Filtered by Event ID 4769](../../images/wazuh-event-4769-dashboard.png)

Expanding the event log overview displays the 4 distinct successful ticket requests corresponding to the harvesting phase:

![Wazuh Event List for Event ID 4769](../../images/wazuh-event-4769-list.png)

---

## Phase 3: Forensic Deep Dive (Wazuh SIEM)

Expanding the raw JSON record of one of the Event ID 4769 logs reveals critical forensic details:

- **Agent Name:** `DC01` (Domain Controller logging the event)
- **Target User Name / Requester:** `bob.finance` (The compromised account used to request the ticket)
- **Service Name:** `svc-backup` (The service principal target)
- **Ticket Encryption Type:** `0x17` (RC4-HMAC)
- **Client IP Address:** `::1` or the specific workstation IP requesting the ticket

![Wazuh Event 4769 Raw Details](../../images/wazuh-event-4769-expanded.png)

---

### Custom Sigma Detection Rule

Because RC4 encryption (`0x17`) is a legacy protocol that is significantly faster to crack offline using tools like Hashcat than modern AES-128 or AES-256 encryption, its usage is a strong indicator of a Kerberoasting attack.

The custom Sigma rule designed to detect this behavior:

```yaml
title: Kerberoasting via RC4 Ticket Request
id: 4f8e0d3a-1234-4abc-8def-0123456789ab
status: stable
description: Detects Kerberoasting attack via RC4 encrypted TGS request
references:
  - https://attack.mitre.org/techniques/T1558/003/
tags:
  - attack.credential_access
  - attack.t1558.003
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769
    TicketEncryptionType: '0x17'
    ServiceName|endswith:
      - '$'
  filter:
    ServiceName: 'krbtgt'
  condition: selection and not filter
falsepositives:
  - Legacy applications using RC4
level: high
```

*Note: The rule filters out `krbtgt` because TGS requests to the Key Distribution Center service account are extremely noisy and generate high false positives during normal user authentication.*

---

## Why This Matters

Kerberoasting is completely silent to traditional logon monitoring because it does not trigger any failed authentication events (Event 4625). An attacker with standard user privileges can request tickets for hundreds of service accounts without locking them out. Building detections based on `EventID: 4769` and `TicketEncryptionType: 0x17` (RC4) allows blue teams to identify ticket harvesting in real time before cracking attempts begin offline.

---

## Remediation Recommendations

1. **Disable RC4 Encryption:** Enforce AES-only encryption (`msDS-SupportedEncryptionTypes`) on all service accounts to render offline cracking computationally infeasible.
2. **Implement Group Managed Service Accounts (gMSA):** Migrate service accounts to gMSAs. gMSAs use complex, 240-character, automatically rotated passwords that are practically uncrackable offline.
3. **Configure Strong Password Policy:** If gMSA is not possible, enforce a minimum 25+ character password length for service accounts.
4. **Monitor RC4 TGS Requests:** Create high-severity alerts in the SIEM for any Event ID 4769 where `TicketEncryptionType` is `0x17` and the service requested is not a computer object or `krbtgt`.
