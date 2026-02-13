---
title: HackTheBox — Previous 
date: 2026-01-02 00:00:00 +0800      
categories: [hackthebox machines]          
tags: [hackthebox]         
toc: true                           
comments: false                    
math: false                          
mermaid: false                
---

- **OS**: Linux
- **Difficulty**: Medium

![image-20260214031115938](assets/img/image-20260214031115938.png)

## Service Enumeration

**Port Scan Results**

```
└─$ sudo nmap -Pn 10.10.11.83 -sVC         
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-24 05:06 EDT

Nmap scan report for 10.10.11.83
Host is up (0.25s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://previous.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.58 seconds
```

## Initial Access — next.js

進入首頁用 wappalyzer 發現 Next.js 為 15.2.2

Next.js <15.2.3 有 CVE-2025–29927 middleware 權限繞過漏洞

- [https://github.com/MuhammadWaseem29/CVE-2025-29927-POC](https://github.com/MuhammadWaseem29/CVE-2025-29927-POC)

![image-20260214031119570](assets/img/image-20260214031119570.png)

PoC 參考 [https://github.com/MuhammadWaseem29/CVE-2025-29927-POC](https://github.com/MuhammadWaseem29/CVE-2025-29927-POC)

先請求 /docs , header 加上

X-Middleware-Subrequest: middleware:middleware:middleware:middleware:middleware 以繞過權限檢查

![image-20260214031124500](assets/img/image-20260214031124500.png)

![image-20260214031127424](assets/img/image-20260214031127424.png)

/docs/examples

![image-20260214031131528](assets/img/image-20260214031131528.png)

發現 LFI 路徑 /api/download?example=

![image-20260214031133866](assets/img/image-20260214031133866.png)

查看環境變數, 啟動路徑是 `/app`

![image-20260214031137502](assets/img/image-20260214031137502.png)

查看 next.js 路由配置文件, 其中 /api/auth/[…nextauth] 很可疑

![image-20260214031139748](assets/img/image-20260214031139748.png)

果真發現硬編碼 jeremy:MyNameIsJeremyAndILovePancakes

![image-20260214031142274](assets/img/image-20260214031142274.png)

ssh 登入 jeremy

![image-20260214031144993](assets/img/image-20260214031144993.png)

**user.txt value:**

```
jeremy@previous:~$ cat user.txt 
<REDACTED>
```

## Privilege Escalation

sudo -l 結果顯示可以 以 root 權限執行 terraform

Terraform是由HashiCorp開發的一款開源的「基礎設施即程式碼」（Infrastructure as Code, IaC）工具

![image-20260214031148096](assets/img/image-20260214031148096.png)

到 `/opt/examples` 的 `main.tf` 看 source 名稱為 previous.htb/terraform/examples

![image-20260214031150226](assets/img/image-20260214031150226.png)

查看 terraform 官網, 發現可以使用環境變數 `TF_CLI_CONFIG_FILE` 指向自己建立的惡意 provider

- [https://developer.hashicorp.com/terraform/cli/config/environment-variables#tf_cli_config_file](https://developer.hashicorp.com/terraform/cli/config/environment-variables#tf_cli_config_file)

![image-20260214031152982](assets/img/image-20260214031152982.png)

建立惡意 provider

![image-20260214031157440](assets/img/image-20260214031157440.png)

取得 root shell

![image-20260214031159582](assets/img/image-20260214031159582.png)

**root.txt value:**

```bash
bash-5.1# cat /root/root.txt 
<REDACTED>
```
