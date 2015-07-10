import nose
import os
import sys

sys.path.insert(0, '../')


from pkilib import ssl


WRKDIR = './workspace'
CFG = '{0}/test.cfg'.format(WRKDIR)
KEY = '{0}/test.key'.format(WRKDIR)
CRL = '{0}/test.crl'.format(WRKDIR)
CRT = '{0}/test.crt'.format(WRKDIR)
PWFILE = '{0}/passwd.input'.format(WRKDIR)
NAME = 'test'


def clean_workspace():
    if os.path.exists(CFG):
        os.unlink(CFG)
    if os.path.exists(KEY):
        os.unlink(KEY)
    if os.path.exists(CRL):
        os.unlink(CRL)
    if os.path.exists(CRT):
        os.unlink(CRT)
    if os.path.exists(PWFILE):
        os.unlink(PWFILE)
    open(PWFILE, 'w').write('{0}\n'.format(NAME))


def test_good_wrkdir():
    assert(ssl.OpenSSL(WRKDIR, CFG, CRL)) != None


@nose.tools.raises(SystemExit)
def test_nonexisting_wrkdir():
    assert(ssl.OpenSSL('somerandompath', CFG, CRL)) == None


def test_crl_nonexisting_cfg():
    openssl = ssl.OpenSSL(WRKDIR, 'somerandomfile', CRL)
    assert(openssl.updatecrl(PWFILE)) == False


def test_crl_nonexisting_pwfile():
    openssl = ssl.OpenSSL(WRKDIR, CFG, CRL)
    assert(openssl.updatecrl('somerandomfile')) == False


@nose.with_setup(clean_workspace)
def test_genkey_no_config():
    openssl = ssl.OpenSSL(WRKDIR, CFG, CRL)
    openssl.genkey('somerandomconfig', NAME, pwfile=PWFILE)
    assert(os.path.exists(CRT)) == False


@nose.with_setup(clean_workspace)
def test_genkey_exists():
    openssl = ssl.OpenSSL(WRKDIR, CFG, CRL)
    openssl.genkey(CFG, NAME, pwfile=PWFILE)
    assert(os.path.exists(CRT)) == True


def test_crl_result():
    openssl = ssl.OpenSSL(WRKDIR, CFG, CRL)
    assert(openssl.updatecrl(PWFILE)) == True
    os.unlink(CRL)


def test_crl_file():
    openssl = ssl.OpenSSL(WRKDIR, CFG, CRL)
    openssl.updatecrl(PWFILE)
    assert(os.path.exists(CRL)) == True
