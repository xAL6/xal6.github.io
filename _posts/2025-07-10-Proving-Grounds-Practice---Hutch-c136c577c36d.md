---
title: Proving Grounds Practice — Hutch          
date: 2025-07-10 00:00:00 +0800      
categories: [proving gounds]          
tags: [proving gounds]         
toc: true                           
comments: false                    
math: false                          
mermaid: false                       
---

- **OS**: Windows Active Directory
- **Difficulty**: Intermediate

## Service Enumeration

**Port Scan Results**

**TCP**: 53, 80, 88, 135, 139, 389, 445, 464, 593, 636, 3268, 3269, 5985, 9389, 49666, 49668, 49673, 49674, 49676, 49692, 49757

**UDP**: 53, 88, 123, 389

We run nmapAutomator to scan the target and found a few ports open.

> [nmapAutomator - GitHub](https://github.com/21y4d/nmapAutomator)

```bash
└─$ sudo ~/nmapAutomator/nmapAutomator.sh 192.168.150.122 All                
[sudo] password for kali: 

Running all scans on 192.168.150.122

Host is likely running Unknown OS!


---------------------Starting Port Scan-----------------------



PORT     STATE SERVICE
53/tcp   open  domain
80/tcp   open  http
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
5985/tcp open  wsman



---------------------Starting Script Scan-----------------------



PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE COPY PROPFIND DELETE MOVE PROPPATCH MKCOL LOCK UNLOCK PUT
|_http-title: IIS Windows Server
| http-webdav-scan: 
|   Server Type: Microsoft-IIS/10.0
|   Server Date: Thu, 10 Jul 2025 01:12:16 GMT
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, POST, COPY, PROPFIND, DELETE, MOVE, PROPPATCH, MKCOL, LOCK, UNLOCK
|   WebDAV type: Unknown
|_  Public Options: OPTIONS, TRACE, GET, HEAD, POST, PROPFIND, PROPPATCH, MKCOL, PUT, DELETE, COPY, MOVE, LOCK, UNLOCK
|_http-server-header: Microsoft-IIS/10.0
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-07-10 01:12:10Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: hutch.offsec0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: hutch.offsec0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: HUTCHDC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-07-10T01:12:18
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required



---------------------Starting Full Scan------------------------


PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
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
5985/tcp  open  wsman
9389/tcp  open  adws
49666/tcp open  unknown
49668/tcp open  unknown
49673/tcp open  unknown
49674/tcp open  unknown
49676/tcp open  unknown
49692/tcp open  unknown
49757/tcp open  unknown



Making a script scan on extra ports: 9389, 49666, 49668, 49673, 49674, 49676, 49692, 49757


PORT      STATE SERVICE    VERSION
9389/tcp  open  mc-nmf     .NET Message Framing
49666/tcp open  msrpc      Microsoft Windows RPC
49668/tcp open  msrpc      Microsoft Windows RPC
49673/tcp open  ncacn_http Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc      Microsoft Windows RPC
49676/tcp open  msrpc      Microsoft Windows RPC
49692/tcp open  msrpc      Microsoft Windows RPC
49757/tcp open  msrpc      Microsoft Windows RPC
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
88/udp  open  kerberos-sec Microsoft Windows Kerberos (server time: 2025-07-10 01:19:03Z)
123/udp open  ntp          NTP v3
389/udp open  ldap         Microsoft Windows Active Directory LDAP (Domain: hutch.offsec0., Site: Default-First-Site-Name)
Service Info: Host: HUTCHDC; OS: Windows; CPE: cpe:/o:microsoft:windows
```

## Initial Access and Privilege Escalation — User Description Password leak and ReadLAPSPassword

ldap anonymous bind present, so we enumerate all users, and found credentials **fmcsorley:CrabSharkJellyfish192** in Description.

![image-20260211032705615](assets/img/image-20260211032705615.png)

Run bloodhound.

![image-20260211032709250](assets/img/image-20260211032709250.png)

![image-20260211032713952](assets/img/image-20260211032713952.png)

user fmcsorley can read local administrator's password on the computer HUTCHDC.HUTCH.OFFSEC.

![ReadLAPSPassword](https://cdn-images-1.medium.com/max/800/1*9g0WZPg-nwGQsthHWoTqig.png)

![image-20260211032717437](assets/img/image-20260211032717437.png)

We used bloodyAD to read paintext password of local administrator.

![image-20260211032721389](assets/img/image-20260211032721389.png)

impacket-psexec login and get root shell.

![image-20260211032726470](assets/img/image-20260211032726470.png)

**local.txt value:** ac374940c61b87f33da65990729f57e9

![image-20260211032730154](assets/img/image-20260211032730154.png)

## Post Exploitation

**proof.txt value:** 198c457ca87828a15e8b17cb0c50d497

![image-20260211032735255](assets/img/image-20260211032735255.png)
