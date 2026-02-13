---
title: Proving Grounds Practice — Nickel        
date: 2025-07-11 00:00:00 +0800      
categories: [proving gounds]          
tags: [proving gounds]         
toc: true                           
comments: false                    
math: false                          
mermaid: false                       
---

- **OS**: Windows
- **Difficulty**: Hard

## Service Enumeration

**Port Scan Results**

**TCP**: 21, 22, 80, 135, 139, 445, 3389, 8089, 5040, 7680, 33333, 49664, 49665, 49666, 49667, 49668, 49669

We run nmapAutomator to scan the target and found a few ports open.

> [nmapAutomator - GitHub](https://github.com/21y4d/nmapAutomator)

```
└─$ sudo ~/nmapAutomator/nmapAutomator.sh 192.168.138.99 All 
[sudo] password for kali: 

Running all scans on 192.168.138.99

Host is likely running Unknown OS!


---------------------Starting Port Scan-----------------------



PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
80/tcp   open  http
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3389/tcp open  ms-wbt-server
8089/tcp open  unknown



---------------------Starting Script Scan-----------------------



PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           FileZilla ftpd 0.9.60 beta
| ftp-syst: 
|_  SYST: UNIX emulated by FileZilla
22/tcp   open  ssh           OpenSSH for_Windows_8.1 (protocol 2.0)
| ssh-hostkey: 
|   3072 86:84:fd:d5:43:27:05:cf:a7:f2:e9:e2:75:70:d5:f3 (RSA)
|   256 9c:93:cf:48:a9:4e:70:f4:60:de:e1:a9:c2:c0:b6:ff (ECDSA)
|_  256 00:4e:d7:3b:0f:9f:e3:74:4d:04:99:0b:b1:8b:de:a5 (ED25519)
80/tcp   open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Site doesn't have a title.
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=nickel
| Not valid before: 2025-07-09T21:22:56
|_Not valid after:  2026-01-08T21:22:56
| rdp-ntlm-info: 
|   Target_Name: NICKEL
|   NetBIOS_Domain_Name: NICKEL
|   NetBIOS_Computer_Name: NICKEL
|   DNS_Domain_Name: nickel
|   DNS_Computer_Name: nickel
|   Product_Version: 10.0.18362
|_  System_Time: 2025-07-10T21:25:02+00:00
|_ssl-date: 2025-07-10T21:26:08+00:00; 0s from scanner time.
8089/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Site doesn't have a title.
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2025-07-10T21:25:04
|_  start_date: N/A



OS Detection modified to: Windows



---------------------Starting Full Scan------------------------


PORT      STATE SERVICE
21/tcp    open  ftp
22/tcp    open  ssh
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
3389/tcp  open  ms-wbt-server
5040/tcp  open  unknown
7680/tcp  open  pando-pub
8089/tcp  open  unknown
33333/tcp open  dgi-serv
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  unknown



Making a script scan on extra ports: 5040, 7680, 33333, 49664, 49665, 49666, 49667, 49668, 49669


PORT      STATE SERVICE VERSION
5040/tcp  open  unknown
33333/tcp open  http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Site doesn't have a title.
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc   Microsoft Windows RPC
49665/tcp open  msrpc   Microsoft Windows RPC
49666/tcp open  msrpc   Microsoft Windows RPC
49667/tcp open  msrpc   Microsoft Windows RPC
49668/tcp open  msrpc   Microsoft Windows RPC
49669/tcp open  msrpc   Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

## Initial Access — SSH

![image-20260211032816074](assets/img/image-20260211032816074.png)

**local.txt value:** f81b9f9b3632a4cef6ed91801aee4fa8

![image-20260211032819005](assets/img/image-20260211032819005.png)

## Privilege Escalation — Internal Api Code Execution

We saw a pdf file use ftp, and download it.

![image-20260211032822052](assets/img/image-20260211032822052.png)

need password to open.

![image-20260211032824935](assets/img/image-20260211032824935.png)

use pdf2john to transfer pdf for to hash, then use hashcat to crack password.

![image-20260211032828640](assets/img/image-20260211032828640.png)

![image-20260211032831574](assets/img/image-20260211032831574.png)

pdf password is **ariah4168**

![image-20260211032834319](assets/img/image-20260211032834319.png)

open pdf with password **ariah4168**, and saw command endpoint http://nickel, it seems there is an internal api we can execute code.

![image-20260211032837939](assets/img/image-20260211032837939.png)

Use ssh dynamic port forwarding to forward the traffice through proxy 127.0.0.1:1080 to target localhost.

![image-20260211032840111](assets/img/image-20260211032840111.png)

add dns entry to /etc/hosts.

![image-20260211032842794](assets/img/image-20260211032842794.png)

![image-20260211032845274](assets/img/image-20260211032845274.png)

add socks5 proxy to foxproxy.

![image-20260211032848008](assets/img/image-20260211032848008.png)

success execute the command whoami.

![image-20260211032851343](assets/img/image-20260211032851343.png)

generate reverse shell payload.

> [Online - Reverse Shell Generator](https://www.revshells.com/)

![image-20260211032853457](assets/img/image-20260211032853457.png)

copy and paste then execute, we got reverse shell with system privilege.

![image-20260211032856431](assets/img/image-20260211032856431.png)

![image-20260211032858479](assets/img/image-20260211032858479.png)

## Post Exploitation

**proof.txt value:** 24daed6de728d0b6a8220d1eefae043a

![image-20260211032900511](assets/img/image-20260211032900511.png)
