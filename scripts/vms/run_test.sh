#!/bin/bash

clear
./scripts/vms/vmsbundle -d -f ./config/pki.yml
echo -e 'bin\nhash\nprompt\ncd [temp]\nput pki-vms.zip\n' | ftp -4 waldorf
rm -f ./workspace/client.yml
echo '[+] Please run the installer on VMS and press a key to continue'
read
./scripts/pkiclient -d -f ./workspace/client.yml -w ./workspace -o ./workspace newcert -u http://10.42.15.17:4392
./scripts/pkiclient -d -f ./workspace/client.yml -w ./workspace -o ./workspace revoke
