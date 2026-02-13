---
title: Proving Grounds Practice — Vault         
date: 2025-07-10 00:00:00 +0800      
categories: [proving gounds]          
tags: [proving gounds]         
toc: true                           
comments: false                    
math: false                          
mermaid: false                       
---

- **OS**: Windows Active Directory
- **Difficulty**: Hard

## Service Enumeration

**Port Scan Results**

**TCP**: 53, 88, 135, 139, 389, 445, 464, 593, 636, 3268, 3269, 3389, 5985, 9389, 49666, 49668, 49673, 49674, 49679, 49703, 49811

**UDP**: 53, 88, 123, 389

We run nmapAutomator to scan the target and found a few ports open.

> [nmapAutomator - GitHub](https://github.com/21y4d/nmapAutomator)

```bash
└─$ sudo ~/nmapAutomator/nmapAutomator.sh 192.168.118.172 All
[sudo] password for kali: 

Running all scans on 192.168.118.172

Host is likely running Unknown OS!


---------------------Starting Port Scan-----------------------



PORT     STATE SERVICE
53/tcp   open  domain
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
389/tcp  open  ldap
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  http-rpc-epmap
636/tcp  open  ldapssl
3268/tcp open  globalcatLDAP
3269/tcp open  globalcatLDAPssl
3389/tcp open  ms-wbt-server
5985/tcp open  wsman



---------------------Starting Script Scan-----------------------



PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-07-10 05:07:34Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: vault.offsec0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: vault.offsec0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=DC.vault.offsec
| Not valid before: 2025-07-09T05:04:36
|_Not valid after:  2026-01-08T05:04:36
| rdp-ntlm-info: 
|   Target_Name: VAULT
|   NetBIOS_Domain_Name: VAULT
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: vault.offsec
|   DNS_Computer_Name: DC.vault.offsec
|   DNS_Tree_Name: vault.offsec
|   Product_Version: 10.0.17763
|_  System_Time: 2025-07-10T05:07:44+00:00
|_ssl-date: 2025-07-10T05:08:24+00:00; 0s from scanner time.
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-07-10T05:07:47
|_  start_date: N/A



---------------------Starting Full Scan------------------------


PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
3389/tcp  open  ms-wbt-server
5985/tcp  open  wsman
9389/tcp  open  adws
49666/tcp open  unknown
49668/tcp open  unknown
49673/tcp open  unknown
49674/tcp open  unknown
49679/tcp open  unknown
49703/tcp open  unknown
49811/tcp open  unknown



Making a script scan on extra ports: 9389, 49666, 49668, 49673, 49674, 49679, 49703, 49811


PORT      STATE SERVICE    VERSION
9389/tcp  open  mc-nmf     .NET Message Framing
49666/tcp open  msrpc      Microsoft Windows RPC
49668/tcp open  msrpc      Microsoft Windows RPC
49673/tcp open  ncacn_http Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc      Microsoft Windows RPC
49679/tcp open  msrpc      Microsoft Windows RPC
49703/tcp open  msrpc      Microsoft Windows RPC
49811/tcp open  msrpc      Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows




----------------------Starting UDP Scan------------------------


PORT    STATE SERVICE
53/udp  open  domain
88/udp  open  kerberos-sec
123/udp open  ntp
389/udp open  ldap


Making a script scan on UDP ports: 53, 88, 123, 389


PORT    STATE SERVICE      VERSION
53/udp  open  domain       (generic dns response: SERVFAIL)
| fingerprint-strings: 
|   DNS-SD: 
|     _services
|     _dns-sd
|     _udp
|     local
|   NBTStat: 
|_    CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
88/udp  open  kerberos-sec Microsoft Windows Kerberos (server time: 2025-07-10 05:14:34Z)
123/udp open  ntp          NTP v3
389/udp open  ldap         Microsoft Windows Active Directory LDAP (Domain: vault.offsec0., Site: Default-First-Site-Name)
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows
```

## Initial Access — winrm

Because user is in remote management users group, we use **anirudh:SecureHM** login.

![image-20260211032742098](assets/img/image-20260211032742098.png)

**local.txt value:** 6c499ba7cb36960e7dbab1add8ecfd2f

![image-20260211032744614](assets/img/image-20260211032744614.png)

## Privilege Escalation — SeRestoreAbuse

We have SeRestorePrivilege

![image-20260211032746937](assets/img/image-20260211032746937.png)

Here's a tool SeRestoreAbuse.

> [GitHub - xct/SeRestoreAbuse: SeRestorePrivilege to SYSTEM](https://github.com/xct/SeRestoreAbuse)

> [SeRestoreAbuse.exe - dxnboy/redteam](https://github.com/dxnboy/redteam/blob/master/SeRestoreAbuse.exe)

upload tool to victum machine.

![image-20260211032750261](assets/img/image-20260211032750261.png)

use msfvenom to generate reverse shell.

![image-20260211032752925](assets/img/image-20260211032752925.png)

upload reverse shell.

![image-20260211032755993](assets/img/image-20260211032755993.png)

execute SeRestoreAbuse.exe with path of reverse shell and get shell.

![image-20260211032758993](assets/img/image-20260211032758993.png)

![image-20260211032801484](assets/img/image-20260211032801484.png)

## Post Exploitation

**proof.txt value:** f78ccf44b7ee38688d0470459f55c3b7

![image-20260211032806688](assets/img/image-20260211032806688.png)
