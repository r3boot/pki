$!
$! This procedure runs the AS65342 PKI API
$!
$!
$ write sys$output "[+] Starting AS65342 PKI API"
$ set def cluster:[temp.pki]
$ python [.scripts]pkiapi.py -d -f ./config/pki.yml -w ./store -l 10.42.15.17
$!
