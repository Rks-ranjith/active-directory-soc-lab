# Attack scenario 1 — Network service discovery

**MITRE ATT&CK:** T1046 — Network Service Discovery
**Date:** May 2026
**Source:** Kali Linux (192.168.100.50)
**Target:** DC01 — Domain Controller (192.168.100.10)

## Objective

Before any meaningful attack against a domain controller, an adversary needs to know what services are exposed. This scenario simulates the reconnaissance phase of an intrusion: identifying open ports and fingerprinting the host as a Windows Active Directory server.

## Attacker Commands

```bash
nmap -sV 192.168.100.10
```

![Real Nmap Scan — lucifer@kali against DC01 (192.168.100.10)](../../images/nmap-scan-dc01.webp)

## Result

```
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: corp.local)
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: corp.local)
3269/tcp open  tcpwrapped
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (WinRM)
```

## Analysis

The combination of ports 88 (Kerberos), 389/3268 (LDAP / Global Catalog), and 445 (SMB) is a definitive fingerprint of a Windows Active Directory Domain Controller. Nmap's service detection also extracted the domain name directly from the LDAP banner (`corp.local`), which an attacker would use to begin building a target list of usernames for the next phase — password spraying.

Port 5985 (WinRM) is notable: if later compromised credentials have administrative rights, this port allows remote PowerShell execution without needing SMB-based tools.

## Detection

A high volume of connections to many distinct ports from a single source IP within a short time window is the core signal for Nmap-style scanning. In this lab, scan detection is handled by Wazuh's `network_scan` rule group combined with Sysmon Event ID 3 (network connection) telemetry forwarded from the Sysmon-instrumented endpoint.

Query used to validate detection (Splunk SPL, also portable to Wazuh's search):

```
index=wineventlog sourcetype="WinEventLog:Sysmon" EventCode=3
| stats dc(dest_port) as unique_ports by src_ip, _time
| where unique_ports > 10
```

## Why this matters

Reconnaissance is the cheapest and lowest-risk phase of an attack for the adversary, and the easiest phase for defenders to catch if logging is in place. A SOC that detects and triages scanning activity before it escalates into credential attacks has a real opportunity to stop an intrusion at the earliest possible stage.

## Remediation recommendation

- Restrict which internal hosts may query AD-related ports (389, 445, 3268) at the network layer where business need does not require it.
- Alert on any single source IP touching more than N distinct ports against a domain controller within a 60-second window.
- Treat unexplained reconnaissance traffic against a DC as a P2 incident requiring investigation, even with no confirmed compromise.
