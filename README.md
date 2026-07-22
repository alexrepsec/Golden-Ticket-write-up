# 🎫 Golden Ticket — LetsDefend Challenge

[![Platform](https://img.shields.io/badge/-LetsDefend-0078D4?style=for-the-badge&logoColor=white)](https://app.letsdefend.io/challenge/golden-ticket)
[![Difficulty](https://img.shields.io/badge/-Hard-FF0000?style=for-the-badge&logoColor=white)]()
[![Category](https://img.shields.io/badge/-Active%20Directory%20IR-6A0DAD?style=for-the-badge&logoColor=white)]()
[![MITRE](https://img.shields.io/badge/-MITRE%20ATT%26CK-FF6600?style=for-the-badge&logoColor=white)](https://attack.mitre.org/techniques/T1558/001/)

---

## 📋 Scenario

> An alert has been triggered within a network, indicating a possible attack on the Domain Controller (DC). The security team has detected suspicious activity suggesting lateral movement attempts from a compromised workstation to the DC. An investigator is tasked with analyzing network traffic, reviewing event logs, and identifying how the attacker is navigating through the environment. The goal is to trace the attacker's steps, determine their access point, and prevent further escalation to the Domain Controller.

**Artifact:** `goldenticket.7z`  
**Password:** `infected`  
**Artifact type:** Windows Security Event Logs (`.evtx`)

---

## 🎯 What is a Golden Ticket Attack?

A **Golden Ticket** attack (T1558.001) occurs when an attacker obtains the **KRBTGT account password hash** from a Domain Controller, enabling them to forge **Kerberos Ticket Granting Tickets (TGTs)** for any account in Active Directory — including privileged accounts like `ADMINISTRATOR`.

Unlike normal Kerberos flows that require the DC to issue each ticket, a forged Golden Ticket bypasses this entirely. The attacker can impersonate any user, access any resource, and maintain persistence indefinitely — even if passwords are changed — until the KRBTGT hash is rotated twice.

```
Normal Kerberos Flow:
  Client → AS-REQ → DC → AS-REP (TGT) → Client → TGS-REQ → DC → TGS-REP → Service

Golden Ticket Attack:
  Attacker forges TGT locally using stolen KRBTGT hash
  → Submits forged TGT directly → DC validates it → Full access granted
```

---

## 🛠️ Tools Used

| Tool | Purpose |
|------|---------|
| Windows Event Viewer | Manual review of Security Event Logs |
| Event Log filtering (XML) | Narrow down relevant Event IDs |
| MITRE ATT&CK | Reference for detection strategies |

**Key Event IDs analyzed:**

| Event ID | Description |
|----------|-------------|
| 4768 | Kerberos Authentication Ticket (TGT) Request (AS-REQ/AS-REP) |
| 4769 | Kerberos Service Ticket Request (TGS-REQ) |
| 4776 | NTLM Credential Validation |
| 4624 | Successful Account Logon |
| 4634 / 4647 | Account Logoff |

---

## 🔍 Investigation

### Step 1 — Narrowing down the logs

The Security event log contained a high volume of Kerberos logon events. To reduce noise and identify the entry point, the log was first filtered by **Event ID 4776** (NTLM Credential Validation), which revealed authentication attempts against a service account.

The filter immediately surfaced activity related to the `SQLSERVICE` account — an atypical service account to be authenticating interactively, making it a strong indicator of compromise.

---

### Q1 — When did the attacker first access the service account within the DC environment?

Pivoting from the 4776 event to **Event ID 4624** (Successful Logon) and filtering by the `SQLSERVICE` account, the first successful logon event was identified, including its timestamp, source IP, and port.

> ✅ **Answer:**
> ```
> 2024-10-05 16:50:29 UTC
> ```

---

### Q2 — What is the name of the compromised service account?

The NTLM validation event (4776) and the corresponding logon event (4624) both identified the same account as the target of the attacker's initial access within the Domain Controller environment.

> ✅ **Answer:**
> ```
> sqlservice
> ```

---

### Q3 — Which IP address and port were used by the attacker to log into the compromised account?

The **Event ID 4624** logon entry for `SQLSERVICE` included the **Network Information** fields, which record the source IP address and source port of the authentication request. This identified the attacker's lateral movement origin point.

> ✅ **Answer:**
> ```
> 192.168.110.129:48858
> ```

---

### Q4 — Before that, the attacker tried an AS-REP attack. What user account was targeted?

Prior to compromising `SQLSERVICE`, the attacker performed an **AS-REP Roasting** attack (T1558.004). This technique targets accounts that have **Kerberos Pre-Authentication disabled** — the DC will respond to AS-REQ messages without verifying the requester's identity, returning an encrypted TGT that can be cracked offline.

Detection method per MITRE ATT&CK: monitor for **Event ID 4768** with:
- `PreAuthType = 0` (pre-authentication disabled)
- `TicketEncryptionType = 0x17` (RC4 — weak/legacy encryption)

Filtering the Security log for these conditions revealed the targeted account.

> ✅ **Answer:**
> ```
> Corrado
> ```

---

### Q5 — When did the attacker request the TGT to perform the AS-REP attack?

The **Event ID 4768** entry for the `Corrado` account with `PreAuthType = 0` and `EncryptionType = 0x17` (RC4) provided the exact timestamp of the AS-REP roasting attempt — occurring before the SQLSERVICE compromise, consistent with the attacker's reconnaissance and credential gathering phase.

> ✅ **Answer:**
> ```
> 2024-10-05 14:42:44 UTC
> ```

---

### Q6 — After gaining DC access, the attacker generated a Golden Ticket to impersonate a DC user. What was the target account?

After compromising `SQLSERVICE` and gaining access to the Domain Controller, the attacker extracted the **KRBTGT hash** and forged a Golden Ticket targeting the highest-privilege account in the domain — a classic objective of this attack chain.

This was confirmed by filtering **Event ID 4624** for logon events occurring after the `SQLSERVICE` compromise, using the keyword `administrator`, which surfaced a logon event with anomalous Kerberos ticket characteristics (abnormal ticket lifetime, RC4 encryption).

> ✅ **Answer:**
> ```
> ADMINISTRATOR
> ```

---

### Q7 — At what time did the attacker try to log in using the Golden Ticket?

The forged Golden Ticket logon event (Event ID 4624, Logon Type 3) for the `ADMINISTRATOR` account appeared approximately one hour after the initial `SQLSERVICE` access, consistent with the time needed for the attacker to dump the KRBTGT hash, forge the ticket, and attempt domain-wide access.

> ✅ **Answer:**
> ```
> 2024-10-05 17:57:03 UTC
> ```

---

## 🗺️ Attack Chain Summary

```
[1] RECONNAISSANCE & INITIAL FOOTHOLD
    └── Attacker identifies Corrado account with Pre-Auth disabled
        └── AS-REP Roasting attack at 2024-10-05 14:42:44 UTC
            └── TGT requested with RC4 (0x17) encryption → cracked offline

[2] LATERAL MOVEMENT TO DOMAIN CONTROLLER
    └── Attacker authenticates as SQLSERVICE from 192.168.110.129:48858
        └── Successful logon to DC at 2024-10-05 16:50:29 UTC
            └── SQLSERVICE account used as pivot into DC environment

[3] KRBTGT HASH EXTRACTION
    └── Attacker dumps KRBTGT hash from Domain Controller
        └── Method: OS Credential Dumping (T1003) — likely DCSync or lsass dump

[4] GOLDEN TICKET FORGERY & PRIVILEGE ESCALATION
    └── Attacker forges TGT for ADMINISTRATOR account locally
        └── Golden Ticket used to authenticate at 2024-10-05 17:57:03 UTC
            └── Full domain compromise achieved — any resource accessible
```

---

## ⏱️ Attack Timeline

| Time (UTC) | Event | Event ID |
|------------|-------|----------|
| 2024-10-05 14:42:44 | AS-REP Roasting attempt against `Corrado` | 4768 |
| 2024-10-05 16:50:29 | Successful logon as `SQLSERVICE` from 192.168.110.129 | 4624 |
| 2024-10-05 ~17:xx:xx | KRBTGT hash extracted from DC | — |
| 2024-10-05 17:57:03 | Golden Ticket used — logon as `ADMINISTRATOR` | 4624 |

---

## 📌 IOCs

| Type | Value |
|------|-------|
| Attacker source IP | `192.168.110.129` |
| Attacker source port | `48858` |
| AS-REP target account | `Corrado` |
| Compromised service account | `sqlservice` |
| DC first access time | `2024-10-05 16:50:29 UTC` |
| AS-REP attack time | `2024-10-05 14:42:44 UTC` |
| Golden Ticket target | `ADMINISTRATOR` |
| Golden Ticket use time | `2024-10-05 17:57:03 UTC` |
| Weak encryption used | RC4 (`0x17`) |
| Pre-Auth disabled account | `Corrado` |

---

## 🧩 MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|-----------|-----|
| Credential Access | AS-REP Roasting | T1558.004 |
| Lateral Movement | Remote Services — Valid Accounts | T1021 |
| Credential Access | OS Credential Dumping (KRBTGT) | T1003 |
| Privilege Escalation | Golden Ticket | T1558.001 |
| Defense Evasion | Use of Valid Accounts | T1078.002 |

---

## 🛡️ Detection & Response Recommendations

**Detect Golden Ticket abuse:**
1. Monitor Event ID **4768** for `PreAuthType = 0` and `EncryptionType = 0x17` (RC4)
2. Flag Kerberos tickets with **abnormally long lifetimes** (default max is 10 hours)
3. Alert on **Event ID 4624** logons where ticket was issued without a prior TGS request
4. Monitor for **DCSync** patterns: a non-DC machine requesting replication via `MS-DRSR`

**Containment:**
1. Rotate the **KRBTGT password twice** (invalidates all existing Golden Tickets)
2. Isolate the attacker's source machine (`192.168.110.129`)
3. Enable Kerberos Pre-Authentication on all accounts (disable AS-REP vulnerability)
4. Enforce **AES256 encryption** — disable RC4/DES in domain Kerberos policy

---

## 📚 References

- [MITRE ATT&CK — T1558.001 Golden Ticket](https://attack.mitre.org/techniques/T1558/001/)
- [MITRE ATT&CK — T1558.004 AS-REP Roasting](https://attack.mitre.org/techniques/T1558/004/)
- [MITRE Detection Strategy DET0113 — AS-REP Monitoring](https://attack.mitre.org/detectionstrategies/DET0113/)
- [LetsDefend — Golden Ticket Challenge](https://app.letsdefend.io/challenge/golden-ticket)

---

*Write-up by [alexrepsec](https://github.com/alexrepsec) — LetsDefend DFIR Series*
