import os

C_OSNAME = os.uname()[0]
C_TMPDIR = '/var/tmp/'

if C_OSNAME == 'OpenVMS':
    C_TMPDIR = '/cluster/temp/'
