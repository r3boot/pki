"""
.. module:: ssl
   :platform: Unix, VMS
   :synopsis: Class wrapping around various functions of openssl

.. moduleauthor:: Lex van Roon <r3boot@r3blog.nl>
"""

import os
import sys
import pprint

try:
    import mako.template
except ImportError:
    print('Failed to import mako, please run "pip install mako"')
    sys.exit(1)

sys.path.append('.')

from pkilib import utils
from pkilib import log

CA_ROOT = 'root'
CA_INTERMEDIARY = 'intermediary'
CA_AUTOSIGN = 'autosign'


class OpenSSL:
    """Class representing a wrapper around the openssl command

    :param basedir: Directory from where to operate the commands
    :type  basedir: str
    :param cfg:     Path to the openssl.cfg for this CA
    :type  cfg:     str
    :param crl:     Path to the crl for this CA
    :type  crl:     str
    """
    ca_data = {}

    def __init__(self, config, ca_type):
        if ca_type not in [CA_ROOT, CA_INTERMEDIARY, CA_AUTOSIGN]:
            log.error('Invalid ca_type: {0}'.format(ca_type))

        ca_name = '{0}-{1}'.format(config['common']['name'], ca_type)
        basedir = '{0}/{1}'.format(config['common']['workspace'], ca_name)
        basedir = os.path.abspath(basedir)
        self.ca_data = {
            'basedir': basedir,
            'templates': '{0}/templates'.format(config['common']['workspace']),
            'cfg': '{0}/cfg/{1}.cfg'.format(basedir, ca_name),
            'key': '{0}/private/{1}.key'.format(basedir, ca_name),
            'csr': '{0}/csr/{1}.csr'.format(basedir, ca_name),
            'crt': '{0}/certs/{1}.crt'.format(basedir, ca_name),
            'crl': '{0}/crl/{1}.crl'.format(basedir, ca_name),
            'db': '{0}/db/{1}.db'.format(basedir, ca_name),
            'db_attr': '{0}/db/{1}.db_attr'.format(basedir, ca_name),
            'crt_idx': '{0}/db/{1}-crt.idx'.format(basedir, ca_name),
            'crl_idx': '{0}/db/{1}-crl.idx'.format(basedir, ca_name),
            'certsdir': '{0}/certs'.format(basedir),
            'ca_type': ca_type,
        }
        self.ca_data.update(config['common'])
        self.ca_data.update(config[ca_type])
        self.ca_data['crypto'] = config['crypto']
        self.ca_data['name'] = ca_name

    def setup_ca_structure(self):
        basedir = self.ca_data['basedir']
        templates = self.ca_data['templates']
        cfg = self.ca_data['cfg']
        db = self.ca_data['db']
        db_attr = self.ca_data['db_attr']
        crt_idx = self.ca_data['crt_idx']
        crl_idx = self.ca_data['crl_idx']

        root_template = '{0}/root.template'.format(templates)

        # Check if root.template exists
        if not os.path.exists(root_template):
            log.warning('{0} does not exist'.format(root_template))
            return False

        # Setup base directory
        if os.path.exists(basedir):
            log.warning('{0} already exists'.format(basedir))
            return False

        log.debug('Creating {0}'.format(basedir))
        os.mkdir(basedir)

        # Setup CA directories
        for DIR in ['certs', 'cfg', 'crl', 'csr', 'db', 'private']:
            dest_dir = '{0}/{1}'.format(basedir, DIR)
            os.mkdir(dest_dir)

        # Initialize databases
        for FILE in [db, db_attr]:
            open(FILE, 'w').write('')

        # Initialize indices
        for FILE in [crt_idx, crl_idx]:
            open(FILE, 'w').write('01\n')

        # Initialize configuration file
        template_data = open(root_template, 'r').read()
        template = mako.template.Template(template_data)
        try:
            cfg_data = template.render(**self.ca_data)
        except NameError as e:
            log.warning('Failed to generate configuration: {0}'.format(e))
            return False
        open(cfg, 'w').write(cfg_data)

        return True

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
        cfg = os.path.abspath(cfg)
        key = '{0}/private/{1}.key'.format(self.ca_data['basedir'], name)
        csr = '{0}/csr/{1}.csr'.format(self.ca_data['basedir'], name)

        if not os.path.exists(cfg):
            log.warning('{0} does not exist'.format(cfg))
            return False
        if os.path.exists(key):
            log.warning('{0} already exists'.format(key))
            return False
        if os.path.exists(csr):
            log.warning('{0} already exists'.format(csr))
            return False
        if self.ca_data['ca_type'] in [CA_ROOT, CA_INTERMEDIARY]:
            if not pwfile:
                log.warning('Need a password file')
                return False
            else:
                if not os.path.exists(pwfile):
                    return False

        cmdline = 'openssl req -new -config {0} -out {1} -keyout {2}'.format(
            cfg, csr, key
        )

        if pwfile:
            cmdline += ' -passout file:{0}'.format(pwfile)
        utils.run(cmdline)
        return os.path.exists(key)

    def selfsign(self, name, extension=None, pwfile=None):
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
        cfg = os.path.abspath(self.ca_data['cfg'])
        csr = '{0}/csr/{1}.csr'.format(self.ca_data['basedir'], name)
        crt = '{0}/certs/{1}.pem'.format(self.ca_data['basedir'], name)

        if not os.path.exists(cfg):
            log.warning('{0} does not exist'.format(cfg))
            return False
        if not os.path.exists(csr):
            log.warning('{0} does not exist'.format(csr))
            return False
        if os.path.exists(crt):
            log.warning('{0} already exists'.format(crt))
            return False
        if self.ca_data['ca_type'] in [CA_ROOT, CA_INTERMEDIARY]:
            if not pwfile:
                log.warning('Need a password file')
                return False
            else:
                if not os.path.exists(pwfile):
                    return False

        cmdline = 'openssl ca -config {0} -in {1} -out {2} -batch'.format(
            cfg, csr, crt
        )
        cmdline += ' -selfsign'
        if extension:
            cmdline += ' -extensions {0}'.format(extension)
        if pwfile:
            cmdline += ' -passin file:{0}'.format(pwfile)

        utils.run(cmdline)
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
        utils.run(cmdline)
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
        basedir = self.ca_data['basedir']

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
        utils.run(cmdline)
        return os.path.exists(crt)


if __name__ == '__main__':
    import yaml
    CFG_FILE = './workspace/unittest/config/pki.yml'
    CFG = '/tmp/blah.cfg'
    NAME = 'test.fqdn'
    config = yaml.load(open(CFG_FILE, 'r').read())
    ssl = OpenSSL(config, CA_ROOT)
    if not ssl.setup_ca_structure():
        print('Failed to initialize CA')
        sys.exit(1)

    if not ssl.genkey(os.path.abspath(CFG), NAME, pwfile='/tmp/blah'):
        print('Failed to generate key')
        sys.exit(1)

    if not ssl.selfsign(NAME, extension='root_ca_ext', pwfile='/tmp/blah'):
        print('Failed to self-sign csr')
        sys.exit(1)
