"""
.. module:: ssl
   :platform: Unix, VMS
   :synopsis: Class wrapping around various functions of openssl

.. moduleauthor:: Lex van Roon <r3boot@r3blog.nl>
"""

import glob
import os

import mako.template

from pkilib import utils
from pkilib import log

CA_ROOT = 'root'
CA_INTERMEDIARY = 'intermediary'
CA_AUTOSIGN = 'autosign'


class OpenSSL(object):
    """Class representing a wrapper around the openssl command

    :param config:  Dictionary containing the PKI configuration file
    :type  config:  dict
    :param ca_type: Type of CA to represent
    :type  ca_type: str
    """
    ca_data = {}
    cert_db = {}

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
            'bundle': '{0}/certs/{1}-bundle.pem'.format(basedir, ca_name),
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

    @staticmethod
    def parse_subject(raw_subject=None):
        """Helper function which parses a string containing a certificate
        subject into a dictionary. It will return False if raw_subject is not
        a string or if it doesnt start with '/'.

        :param raw_subject: OpenSSL subject to parse
        :type  raw_subject: str
        :returns:           Dictionary containing the parsed subject or False
        :rtype:             dict, bool
        """
        if raw_subject is None:
            log.warning('raw_subject cannot be None')
            return False

        try:
            '/' in raw_subject
        except TypeError:
            log.warning('raw_subject needs to be a valid string')
            return False

        if not raw_subject.startswith('/'):
            log.warning('{0} is an invalid subject'.format(raw_subject))
            return False

        raw_subject = raw_subject.strip()[1:]
        subject = {}
        for field in raw_subject.split('/'):
            key, value = field.split('=')
            subject[key] = value
        return subject

    def parse_db_line(self, line):
        """Helper function which parses a line in OpenSSL database format. It
        will return False if line is not a string, or if it cannot be parsed
        into the correct fields.

        :param line:    Single line of OpenSSL database format content
        :type  line:    str
        :returns:       Dictionary containing the information or False
        :rtype:         dict, bool
        """
        if not isinstance(line, str):
            log.warning('line needs to be a string')
            return False
        if '\t' not in line:
            log.warning('{0} is an invalid line'.format(line))

        tokens = line.split('\t')
        if len(tokens) != 6:
            log.warning('Invalid number of fields')
            return False

        status = tokens[0]
        notbefore = tokens[1]
        notafter = tokens[2]
        serial = tokens[3]
        subject = self.parse_subject(tokens[5])

        data = {
            'CN': subject['CN'],
            'status': status,
            'notbefore': notbefore,
            'notafter': notafter,
            'serial': serial,
            'subject': subject,
        }
        return data

    def parse_certificate(self, crt):
        """Helper function which parses a certificate and returns the subject,
        fingerprint and serial in a dictionary. It will return False if the
        certificate does not exist.

        :param crt: Path to the certificate
        :type  crt: str
        :returns:   Dictionary containing the certificate details or False
        :rtype:     dict, bool
        """
        if not os.path.exists(crt):
            log.warning('{0} does not exist'.format(crt))
            return False

        cmdline = 'openssl x509 -in {0} -noout'.format(crt)
        cmdline += ' -subject -fingerprint -serial'

        data = {}
        for line in utils.run(cmdline).split('\n'):
            log.debug(line)
            if line.startswith('subject='):
                raw_subject = line.strip().replace('subject= ', '')
                data['subject'] = self.parse_subject(raw_subject)
            elif line.startswith('serial='):
                data['serial'] = line.strip().replace('serial=', '')
            elif line.startswith('SHA1'):
                data['fp'] = line.strip().replace('SHA1 Fingerprint=', '')
        return data

    def update_cert_db(self):
        """Helper function to update the in-memory certificate database. It
        will return False if the CA database file or the certificate directory
        cannot be found.

        :returns:   Flag indicating the status of the database update
        :rtype:     bool
        """
        dbf = self.ca_data['db']
        certsdir = self.ca_data['certsdir']

        if not os.path.exists(dbf):
            log.warning('{0} does not exist'.format(dbf))
            return False
        if not os.path.exists(certsdir):
            log.warning('{0} does not exist'.format(certsdir))
            return False

        data = {}

        # Pass 1, read the OpenSSL certificate database
        for line in open(dbf, 'r').readlines():
            cert_data = self.parse_db_line(line)
            common_name = cert_data['CN']
            if common_name not in data:
                data[common_name] = []
            data[common_name].append(cert_data)

        # Pass 2, read certificate details from disk
        certs = glob.glob('{0}/[0-9A-Z]*.pem'.format(certsdir))
        for crt in certs:
            cert_data = self.parse_certificate(crt)
            common_name = cert_data['subject']['CN']
            if common_name not in data:
                continue

            cn_certs = []
            for db_crt in data[common_name]:
                if db_crt['serial'] == cert_data['serial']:
                    db_crt.update(cert_data)
                cn_certs.append(db_crt)
            data[common_name] = cn_certs

        self.cert_db = data
        return True

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
        root_template = '{0}/root.template'.format(templates)

        # Check if root.template exists
        if not os.path.exists(root_template):
            log.warning('{0} does not exist'.format(root_template))
            return False

        # Setup base directory
        if os.path.exists(basedir):
            log.warning('{0} already exists'.format(basedir))
            return False

        log.debug('Setting up directory structure for {0} CA'.format(
            self.ca_data['name']
        ))

        os.mkdir(basedir)

        # Setup CA directories
        for directory in ['certs', 'cfg', 'crl', 'csr', 'db', 'private']:
            dest_dir = '{0}/{1}'.format(basedir, directory)
            os.mkdir(dest_dir)

        # Initialize databases
        for new_file in [self.ca_data['db'], self.ca_data['db_attr']]:
            open(new_file, 'w').write('')

        # Initialize indices
        for new_file in [self.ca_data['crt_idx'], self.ca_data['crl_idx']]:
            open(new_file, 'w').write('01\n')

        # Initialize configuration file
        template_data = open(root_template, 'r').read()
        template = mako.template.Template(template_data)
        try:
            cfg_data = template.render(**self.ca_data)
        except NameError as err:
            log.warning('Failed to generate configuration: {0}'.format(err))
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
        if not isinstance(fqdn, str):
            log.warning('fqdn needs to be a string')
            return False
        if '.' not in fqdn:
            log.warning('Need atleast a two-level fqdn')
            return False
        if len(fqdn.split('.')) > 3:
            log.warning('Number of levels cannot exceed 3')
            return False

        log.debug('Generating TLS configuration for {0}'.format(fqdn))
        template_data = open(server_template, 'r').read()
        template = mako.template.Template(template_data)
        template_cfg = self.ca_data
        template_cfg['fqdn'] = fqdn
        template_cfg['san'] = fqdn.split('.')[0]
        try:
            cfg_data = template.render(**template_cfg)
        except NameError as err:
            log.warning('Failed to generate configuration: {0}'.format(err))
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

        log.debug('Generating key and csr for {0}'.format(name))
        cmdline = 'openssl req -new -config {0} -out {1} -keyout {2}'.format(
            cfg, csr, key
        )

        if pwfile:
            cmdline += ' -passout file:{0}'.format(pwfile)
        utils.run(cmdline)
        return os.path.exists(key)

    def selfsign(self, name, pwfile):
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

        if self.ca_data['ca_type'] != CA_ROOT:
            log.warning('{0} CA cannot be self-signed'.format(
                self.ca_data['ca_type']
            ))
            return False
        try:
            open(pwfile, 'r')
        except (TypeError, EnvironmentError):
            log.warning('{0} cannot be read'.format(pwfile))
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

        log.debug('Self-signing certificate for {0} CA'.format(name))
        cmdline = 'openssl ca -config {0} -in {1} -out {2} -batch'.format(
            cfg, csr, crt
        )
        cmdline += ' -selfsign -extensions root_ca_ext'
        cmdline += ' -passin file:{0}'.format(pwfile)
        utils.run(cmdline)
        self.update_cert_db()
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

        log.debug('Updating certificate revocation list for {0} CA'.format(
            self.ca_data['name']
        ))
        cmdline = 'openssl ca -gencrl -config {0} -out {1}'.format(cfg, crl)
        if pwfile:
            cmdline += ' -passin file:{0}'.format(pwfile)
        utils.run(cmdline)
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

        log.debug('Signing intermediary certificate using {0} CA'.format(
            self.ca_data['name']
        ))
        cmdline = 'openssl ca -config {0} -in {1} -out {2} -batch'.format(
            cfg, csr, crt
        )
        cmdline += ' -passin file:{0}'.format(pwfile)
        cmdline += ' -extensions intermediate_ca_ext -enddate {0}'.format(
            utils.gen_enddate(days)
        )
        utils.run(cmdline)
        self.update_cert_db()
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

        log.debug('Signing certificate using {0} CA'.format(
            self.ca_data['name']
        ))
        cmdline = 'openssl ca -config {0} -in {1} -out {2}'.format(
            cfg, csr, crt
        )
        cmdline += ' -batch -extensions server_ext'
        utils.run(cmdline)
        self.update_cert_db()
        return os.path.exists(crt)

    def updatebundle(self, parent=None):
        """Generate a certificate bundle for this CA. It will use the parents
        certificate bundle if it exists, and else it will use the parents
        certificate. This function will return False if one of the following
        conditions is met:

        * parent is not an ssl.OpenSSL object
        * The parents certificate could not be found
        * The certificate for this CA could not be found

        :param parent:  Instance of the parent CA
        :type  parent:  ssl.OpenSSL
        :returns:       Flag indicating the creation of the bundle
        :rtype:         bool
        """
        if not isinstance(parent, OpenSSL):
            log.warning('parent needs to be an ssl.OpenSSL object')
            return False

        parent_crt = None
        if os.path.exists(parent.ca_data['bundle']):
            parent_crt = parent.ca_data['bundle']
        elif os.path.exists(parent.ca_data['crt']):
            parent_crt = parent.ca_data['crt']
        else:
            log.warning('Cannot find a parent certificate')
            return False

        if not os.path.exists(self.ca_data['crt']):
            log.warning('{0} does not exist'.format(self.ca_data['crt']))
            return False

        log.debug('Updating certificate bundle for {0} CA'.format(
            self.ca_data['name']
        ))
        bundle_data = open(self.ca_data['crt'], 'r').read()
        bundle_data += open(parent_crt, 'r').read()

        open(self.ca_data['bundle'], 'w').write(bundle_data)
        return os.path.exists(self.ca_data['bundle'])
