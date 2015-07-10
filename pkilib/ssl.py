"""
.. module:: ssl
   :platform: Unix, VMS
   :synopsis: Class wrapping around various functions of openssl

.. moduleauthor:: Lex van Roon <r3boot@r3blog.nl>
"""

import os

from pkilib import utils
from pkilib import log


class OpenSSL:
    """Class representing a wrapper around the openssl command

    :param basedir: Directory from where to operate the commands
    :type  basedir: str
    :param cfg:     Path to the openssl.cfg for this CA
    :type  cfg:     str
    :param crl:     Path to the crl for this CA
    :type  crl:     str
    """
    def __init__(self, basedir, cfg, crl):
        if not os.path.exists(basedir):
            log.error('{0} does not exist'.format(basedir))
        self._basedir = basedir
        self._cfg = utils.fpath(cfg)
        self._crl = utils.fpath(crl)

    def genkey(self, cfg, name, pwfile=None):
        """Generate a new key and Certificate Signing Request

        :param cfg:     Path to the configuration file to be used
        :type  cfg:     str
        :param name:    Name as mentioned in the CN
        :type  name:    str
        :param pwfile:  Path to the file containing the password for the key
        :type  pwfile:  str
        :returns:       True if the key + csr are generated, False if not
        :rtype:         bool
        """
        key = '{0}/private/{1}.key'.format(self._basedir, name)
        csr = '{0}/csr/{1}.csr'.format(self._basedir, name)

        if not os.path.exists(cfg):
            log.warning('{0} does not exist'.format(cfg))
            return False
        if os.path.exists(key):
            log.warning('{0} already exists'.format(key))
            return False
        if os.path.exists(csr):
            log.warning('{0} already exists'.format(csr))
            return False
        if not os.path.exists(pwfile):
            log.warning('{0} does not exists'.format(pwfile))
            return False

        cmdline = 'openssl req -new -config {0} -out {1} -keyout {2}'.format(
            cfg, csr, key
        )
        if pwfile:
            cmdline += ' -passout file:{0}'.format(pwfile)
        old_cwd = os.getcwd()
        os.chdir(self._basedir)
        utils.run(cmdline)
        os.chdir(old_cwd)
        return os.path.exists(key)

    def selfsign(self, cfg, name, extension=None, pwfile=None):
        """Sign a certificate

        :param cfg:         Path to configuration to use for signing
        :type  cfg:         str
        :param name:        Name as mentioned in the CN
        :type  name:        str
        :param selfsign:    If set to true, make a self-signed certificate
        :type  selfsign:    bool
        :returns:           True if the certificate was signed, False if not
        :rtype:             bool
        """
        csr = '{0}/csr/{1}.csr'.format(self._basedir, name)
        crt = '{0}/certs/{1}.pem'.format(self._basedir, name)

        if not os.path.exists(cfg):
            log.warning('{0} does not exist'.format(cfg))
            return False
        if not os.path.exists(csr):
            log.warning('{0} does not exist'.format(csr))
            return False
        if os.path.exists(crt):
            log.warning('{0} already exists'.format(crt))
            return False

        cmdline = 'openssl ca -config {0} -in {1} -out {2} -batch'.format(
            cfg, csr, crt
        )
        cmdline += ' -selfsign'
        if extension:
            cmdline += ' -extensions {0}'.format(extension)
        if pwfile:
            cmdline += ' -passin file:{0}'.format(pwfile)
        old_cwd = os.getcwd()
        os.chdir(self._basedir)
        utils.run(cmdline)
        os.chdir(old_cwd)
        return os.path.exists(crt)

    def updatecrl(self, pwfile):
        """Update the Certificate Revocation List for this CA

        :param pwfile:  Path to a file containing the password for the CA key
        :type  pwfile:  str
        :returns:       True if the CRL was created, else False
        :rtype:         bool
        """
        if not os.path.exists(pwfile):
            log.warning('{0} does not exist'.format(pwfile))
            return False

        cmdline = 'openssl ca -gencrl -config {0} -out {1}'.format(
            self._cfg, self._crl
        )

        cmdline += ' -passin file:{0}'.format(pwfile)
        old_cwd = os.getcwd()
        os.chdir(self._basedir)
        utils.run(cmdline)
        os.chdir(old_cwd)

        return os.path.exists(self._crl)

    def sign_intermediary(self, csr, crt, pwfile, days):
        """Sign an intermediary certificate using this CA

        :param csr:     Path to a file containing the CSR for the intermediary
        :type  csr:     str
        :param crt:     Path to the output certificate
        :type  crt:     str
        :returns:       True if certificate was created, else False
        :rtype:         bool
        """
        if not os.path.exists(csr):
            log.warning('{0} does not exist'.format(csr))
            return False
        if os.path.exists(crt):
            log.warning('{0} already exists'.format(crt))
            return False
        if not os.path.exists(pwfile):
            log.warning('{0} does not exist'.format(pwfile))
            return False

        cmdline = 'openssl ca -config {0} -in {1} -out {2} -batch'.format(
            self._cfg,
            utils.fpath(csr),
            utils.fpath(crt),
        )
        cmdline += ' -passin file:{0}'.format(pwfile)
        cmdline += ' -extensions intermediate_ca_ext -enddate {0}'.format(
            utils.gen_enddate(days)
        )
        old_cwd = os.getcwd()
        os.chdir(self._basedir)
        utils.run(cmdline)
        os.chdir(old_cwd)
        return os.path.exists(crt)
