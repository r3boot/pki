"""
.. module:: ssl
   :platform: Unix, VMS
   :synopsis: Class wrapping around various functions of openssl

.. moduleauthor:: Lex van Roon <r3boot@r3blog.nl>
"""

import os
import sys

import mako.template

sys.path.append('.')

from pkilib import utils
from pkilib import log

CA_ROOT = 'root'
CA_INTERMEDIARY = 'intermediary'
CA_AUTOSIGN = 'autosign'


class OpenSSL:
    """Class representing a wrapper around the openssl command

    :param config:  Dictionary containing the PKI configuration file
    :type  config:  dict
    :param ca_type: Type of CA to represent
    :type  ca_type: str
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
            'crt': '{0}/certs/{1}.pem'.format(basedir, ca_name),
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
        """Creates the directory structure for this CA and initializes it's
        databases. It will return False for various errors, these include:

        * An existing base directory
        * A missing root.template
        * Failure to parse the template

        :returns:   Flag indicating the success of this function
        :rtype:     bool
        """
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

    def gen_server_cfg(self, fqdn=None):
        """Generate configuration data for a TLS server request. When called
        with a valid fqdn, it will return a string containing the configuration
        data for a TLS server request. The fqdn can contain two or three
        elements. It will return False if one of the following conditions is
        true:

        * The fqdn is invalid
        * The tls_server.template cannot be found
        * The template could not be parsed

        :param fqdn:    Fully-Qualified domain-name for the server
        :type  fqdn:    str
        :returns:       String containing the configuration, else False
        :rtype:         str, bool
        """
        templates = self.ca_data['templates']
        server_template = '{0}/tls_server.template'.format(templates)

        if not os.path.exists(server_template):
            log.warning('{0} does not exist'.format(server_template))
            return False
        if fqdn is None:
            log.warning('Need a fqdn to generate configuration for')
            return False
        if fqdn == '':
            log.warning('Need a fqdn to generate configuration for')
            return False
        if '.' not in fqdn:
            log.warning('Need atleast a two-level fqdn')
            return False
        if len(fqdn.split('.')) > 3:
            log.warning('Number of levels cannot exceed 3')
            return False

        template_data = open(server_template, 'r').read()
        template = mako.template.Template(template_data)
        template_cfg = self.ca_data
        template_cfg['fqdn'] = fqdn
        template_cfg['san'] = fqdn.split('.')[0]
        try:
            cfg_data = template.render(**template_cfg)
        except NameError as e:
            log.warning('Failed to generate configuration: {0}'.format(e))
            return False
        return cfg_data

    def genkey(self, cfg, name, pwfile=None):
        """Generate a new key and Certificate Signing Request. Cfg is a path
        pointing towards the configuration file which should be used for the
        CSR. The name is the name which will be used for this certificate. This
        function will return False if one of the following conditions is met:

        * The configuration file could not be found
        * The CSR or key already exists
        * pwfile is missing (if ca_type is CA_ROOT or CA_INTERMEDIARY)

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

    def selfsign(self, name, pwfile=None):
        """Self-sign a certificate. It expects the following conditions to be
        true. If one of them is not met, this function will return False:

        * The ca_type is not CA_ROOT
        * pwfile cannot be found
        * The CSR or configuration file cannot be found
        * The certificate already exists

        :param name:        Name as mentioned in the CN
        :type  name:        str
        :returns:           True if the certificate was signed, False if not
        :rtype:             bool
        """
        cfg = os.path.abspath(self.ca_data['cfg'])
        csr = '{0}/csr/{1}.csr'.format(self.ca_data['basedir'], name)
        crt = '{0}/certs/{1}.pem'.format(self.ca_data['basedir'], name)

        if self.ca_data['ca_type'] == CA_ROOT:
            if not pwfile:
                log.warning('Need a password file')
                return False
            else:
                if not os.path.exists(pwfile):
                    return False
        else:
            log.warning('{0} CA cannot be self-signed'.format(
                self.ca_data['ca_type']
            ))
            return False
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
        cmdline += ' -selfsign -extensions root_ca_ext'
        cmdline += ' -passin file:{0}'.format(pwfile)
        utils.run(cmdline)
        return os.path.exists(crt)

    def updatecrl(self, pwfile=None):
        """Update the Certificate Revocation List for this CA. It will return
        False if one of the following conditions is met:

        * pwfile was not found (for ca_type == CA_root or CA_INTERMEDIARY)
        * The configuration file could not be found

        :param pwfile:  Path to a file containing the password for the CA key
        :type  pwfile:  str
        :returns:       True if the CRL was created, else False
        :rtype:         bool
        """
        cfg = os.path.abspath(self.ca_data['cfg'])
        crl = os.path.abspath(self.ca_data['crl'])

        if self.ca_data['ca_type'] in [CA_ROOT, CA_INTERMEDIARY]:
            if not pwfile:
                log.warning('Need a password file')
                return False
            else:
                if not os.path.exists(pwfile):
                    return False
        if not os.path.exists(cfg):
            log.warning('{0} does not exist'.format(cfg))
            return False

        cmdline = 'openssl ca -gencrl -config {0} -out {1}'.format(cfg, crl)
        if pwfile:
            cmdline += ' -passin file:{0}'.format(pwfile)
        log.debug(utils.run(cmdline))
        return os.path.exists(crl)

    def sign_intermediary(self, csr, crt, pwfile, days):
        """Sign an intermediary certificate using this CA. This function will
        return False when:

        * The configuration file for this CA could not be found
        * The CSR could not be found
        * The certificate already exists
        * pwfile could not be found
        * days is not a number

        :param csr:     Path to a file containing the CSR for the intermediary
        :type  csr:     str
        :param crt:     Path to the output certificate
        :type  crt:     str
        :returns:       True if certificate was created, else False
        :rtype:         bool
        """
        cfg = os.path.abspath(self.ca_data['cfg'])

        if not os.path.exists(cfg):
            log.warning('{0} does not exist'.format(cfg))
            return False
        if not os.path.exists(csr):
            log.warning('{0} does not exist'.format(csr))
            return False
        if os.path.exists(crt):
            log.warning('{0} already exists'.format(crt))
            return False
        if not os.path.exists(pwfile):
            log.warning('{0} does not exist'.format(pwfile))
            return False
        try:
            int(days)
        except ValueError:
            log.warning('days needs to be a number')
            return False

        cmdline = 'openssl ca -config {0} -in {1} -out {2} -batch'.format(
            cfg, csr, crt
        )
        cmdline += ' -passin file:{0}'.format(pwfile)
        cmdline += ' -extensions intermediate_ca_ext -enddate {0}'.format(
            utils.gen_enddate(days)
        )
        utils.run(cmdline)
        return os.path.exists(crt)

    def sign(self, name):
        """Sign a certificate using this CA. Name must be a valid fqdn. This
        function will return False if one of the following conditions is met:

        * Name is invalid
        * The configuration file for this CA could not be found
        * The CSR for name could not be found
        * The certificate for name already exists

        :param name:    Name of the certificate to sign
        :type  name:    str
        :returns:       True if certificate was created, else False
        :rtype:         bool
        """
        cfg = os.path.abspath(self.ca_data['cfg'])
        csr = '{0}/csr/{1}.csr'.format(self.ca_data['basedir'], name)
        crt = '{0}/certs/{1}.pem'.format(self.ca_data['basedir'], name)

        if name is None:
            log.warning('Need a fqdn to sign a certificate for')
            return False
        if name == '':
            log.warning('Fqdn cannot be empty')
            return False
        if not os.path.exists(cfg):
            log.warning('{0} does not exist'.format(cfg))
            return False
        if not os.path.exists(csr):
            log.warning('{0} does not exist'.format(csr))
            return False
        if os.path.exists(crt):
            log.warning('{0} already exists'.format(crt))
            return False

        cmdline = 'openssl ca -config {0} -in {1} -out {2}'.format(
            cfg, csr, crt
        )
        cmdline += ' -batch -extensions server_ext'
        log.debug(cmdline)
        log.debug(utils.run(cmdline))
        return os.path.exists(crt)
