from Crypto.Hash    import SHA256

import os
import random


def gentoken():
    sha = SHA256.new()
    sha.update(str(random.random()))
    return sha.hexdigest()


def mkstemp(prefix=''):
    fname = '{0}{1}.tmp'.format(prefix, gentoken()[0:6])
    fd = open(fname, 'w')
    return fd


def cfname(name):
    if os.uname()[0] != 'OpenVMS':
        return name
    t = name.split('/')[1:]
    device = t[0]
    path = '.'.join(t[1:len(t)-1])
    fil = t[len(t)-1]
    return '{0}:[{1}]{2}'.format(device, path, fil)


def cfhost(name):
    if os.uname()[0] != 'OpenVMS':
        return name
    return name.replace('.', '_')

if __name__ == '__main__':
    print(cfname('/cluster/temp/0a7e45.tmp'))
