---
title: Vulnlab — Baby  
date: 2025-07-18 00:00:00 +0800      
categories: [vulnlab machines]          
tags: [vulnlab]         
toc: true                           
comments: false                    
math: false                          
mermaid: false   
image:                              
  path: https://assets.vulnlab.com/baby_slide.png                 
---

- **OS**: Windows Active Directory
- **Difficulty**: Easy

## Service Enumeration

**Port Scan Results**

**TCP**: 53, 88, 135, 139, 389, 445, 464, 593, 636, 3268, 3269, 3389, 5357, 5985, 9389, 49664–52760

**UDP**: 53, 88, 123, 389

We run nmapAutomator to scan the target and found a few ports open.

- [https://github.com/21y4d/nmapAutomator](https://github.com/21y4d/nmapAutomator)

```bash
└─$ sudo ~/nmapAutomator/nmapAutomator.sh 10.10.122.172 All 
[sudo] password for kali: 

Running all scans on 10.10.122.172

No ping detected.. Will not use ping scans!


Host is likely running Unknown OS!


---------------------Starting Port Scan-----------------------



PORT     STATE SERVICE
88/tcp   open  kerberos-sec
389/tcp  open  ldap
464/tcp  open  kpasswd5
593/tcp  open  http-rpc-epmap
636/tcp  open  ldapssl
3268/tcp open  globalcatLDAP
3269/tcp open  globalcatLDAPssl
5357/tcp open  wsdapi
5985/tcp open  wsman



---------------------Starting Script Scan-----------------------


PORT     STATE SERVICE      VERSION
88/tcp   open  kerberos-sec Microsoft Windows Kerberos (server time: 2025-07-17 09:20:01Z)
389/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: baby.vl0., Site: Default-First-Site-Name)
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap         Microsoft Windows Active Directory LDAP (Domain: baby.vl0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
5357/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
5985/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
Service Info: Host: BABYDC; OS: Windows; CPE: cpe:/o:microsoft:windows


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
5357/tcp  open  wsdapi
5985/tcp  open  wsman
9389/tcp  open  adws
49664/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49674/tcp open  unknown
49675/tcp open  unknown
52745/tcp open  unknown
52760/tcp open  unknown


PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: BABY
|   NetBIOS_Domain_Name: BABY
|   NetBIOS_Computer_Name: BABYDC
|   DNS_Domain_Name: baby.vl
|   DNS_Computer_Name: BabyDC.baby.vl
|   Product_Version: 10.0.20348
9389/tcp  open  mc-nmf        .NET Message Framing
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows


----------------------Starting UDP Scan------------------------

PORT    STATE SERVICE
53/udp  open  domain
88/udp  open  kerberos-sec
123/udp open  ntp
389/udp open  ldap

PORT    STATE SERVICE      VERSION
53/udp  open  domain       (generic dns response: SERVFAIL)
88/udp  open  kerberos-sec Microsoft Windows Kerberos (server time: 2025-07-17 09:28:43Z)
123/udp open  ntp          NTP v3
389/udp open  ldap         Microsoft Windows Active Directory LDAP (Domain: baby.vl0., Site: Default-First-Site-Name)
Service Info: Host: BABYDC; OS: Windows; CPE: cpe:/o:microsoft:windows
```

## Initial Access — SMB share to Wordpress RCE

![image-20260214031921860](assets/img/image-20260214031921860.png)

![image-20260214031924136](assets/img/image-20260214031924136.png)

![image-20260214031926596](assets/img/image-20260214031926596.png)

- [https://www.netexec.wiki/smb-protocol/change-user-password](https://www.netexec.wiki/smb-protocol/change-user-password)

![image-20260214031929843](assets/img/image-20260214031929843.png)

![image-20260214031931958](assets/img/image-20260214031931958.png)

## Privilege Escalation — AlwaysInstallElevated

![image-20260214031935178](assets/img/image-20260214031935178.png)

- [https://github.com/giuliano108/SeBackupPrivilege](https://github.com/giuliano108/SeBackupPrivilege)

![image-20260214031937813](assets/img/image-20260214031937813.png)

![image-20260214031940408](assets/img/image-20260214031940408.png)

![image-20260214031943075](assets/img/image-20260214031943075.png)

![image-20260214031945533](assets/img/image-20260214031945533.png)

Administrator:500:aad3b435b51404eeaad3b435b51404ee:ee4457ae59f1e3fbd764e33d9cef123d:::

![image-20260214031948122](assets/img/image-20260214031948122.png)
