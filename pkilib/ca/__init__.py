"""
.. module:: __init__
  :platform: Unix, VMS
  :synopsis: Module containing a base implementation for a CA

.. moduleauthor:: Lex van Roon <r3boot@r3blog.nl>
"""
import os
import sys

try:
    import mako.template
except ImportError:
    print('Failed to import mako, please run "pip install mako"')
    sys.exit(1)

from pkilib import utils
from pkilib import log
from pkilib import ssl

CA_PARENT = 'parent'
CA_ROOT = 'root'
CA_INTERMEDIARY = 'intermediary'
CA_AUTOSIGN = 'autosign'


class ParentCA(ssl.OpenSSL):
    """Class representing a Certificate Authority. This is a wrapper around the
    OpenSSL class.

    :param config: Dictionary containing the contents of the config file
    :type  config: dict
    """
    ca_type = CA_PARENT
    ca_data = {}
    days = 60*60*365*10

    def __init__(self, config):
        if not self.ca_type:
            log.error('ca_type not defined')

        self.config = config
        common = config['common']

        # Setup base variables
        self.name = '{0}-{1}'.format(common['name'], self.ca_type)
        self.workspace = common['workspace']
        self.basedir = '{0}/{1}'.format(common['workspace'], self.name)
        self.crtdir = '{0}/certs'.format(self.basedir)
        cfgdir = '{0}/cfg'.format(self.basedir)
        csrdir = '{0}/csr'.format(self.basedir)
        crldir = '{0}/crl'.format(self.basedir)
        keydir = '{0}/private'.format(self.basedir)
        dbdir = '{0}/db'.format(self.basedir)

        # Some strings are just too long
        bundle_name = '{0}/{1}-bundle.pem'.format(self.crtdir, self.name)
        db_attr_name = '{0}/{1}-db.attr'.format(dbdir, self.name)
        crt_idx_name = '{0}/{1}-crt.idx'.format(dbdir, self.name)
        crl_idx_name = '{0}/{1}-crl.idx'.format(dbdir, self.name)

        # Bundle ca details into a dictionary
        self.ca_data = {
            'baseurl': common['baseurl'],
            'ocspurl': common['ocspurl'],
            'cfg': utils.fpath('{0}/{1}.cfg'.format(cfgdir, self.name)),
            'csr': utils.fpath('{0}/{1}.csr'.format(csrdir, self.name)),
            'crl': utils.fpath('{0}/{1}.crl'.format(crldir, self.name)),
            'key': utils.fpath('{0}/{1}.key'.format(keydir, self.name)),
            'crt': utils.fpath('{0}/{1}.pem'.format(self.crtdir, self.name)),
            'bundle': utils.fpath(bundle_name),
            'db': utils.fpath('{0}/{1}.db'.format(dbdir, self.name)),
            'db_attr': utils.fpath(db_attr_name),
            'crt_idx': utils.fpath(crt_idx_name),
            'crl_idx': utils.fpath(crl_idx_name),
        }

        try:
            self.days = self.config[self.ca_type]['days']
        except KeyError:
            self.days = common['days']

        if not os.path.exists(self.basedir):
            os.mkdir(self.basedir)

        ssl.OpenSSL.__init__(
            self,
            self.basedir,
            self.ca_data['cfg'],
            self.ca_data['crl']
        )

    def setup(self):
        """Initialize the file structure for this CA
        """
        log.info('Setup directories for {0} CA'.format(self.name))
        ca_directories = ['certs', 'cfg', 'crl', 'csr', 'db', 'private']

        for directory in ca_directories:
            fdir = '{0}/{1}'.format(self.basedir, directory)
            if not os.path.exists(fdir):
                log.info('Creating {0}/{1}'.format(self.name, directory))
                os.mkdir(fdir)

        log.info('Initialize databases for {0} CA'.format(self.name))
        for empty_file in [self.ca_data['db'], self.ca_data['db_attr']]:
            open(empty_file, 'w').write('')

        for serial_file in [self.ca_data['crt_idx'], self.ca_data['crl_idx']]:
            open(serial_file, 'w').write('01\n')

        log.info('Installing configuration file for {0} CA'.format(self.name))
        cfgfile = '{0}/cfg/{1}.cfg'.format(self.basedir, self.name)

        cfg = {}
        cfg.update(self.config['common'])

        if self.ca_type != CA_PARENT:
            cfg.update(self.config[self.ca_type])
        else:
            cfg['cn'] = '{0} CA'.format(CA_PARENT)

        cfg.update(self.ca_data)

        cfg['crypto'] = self.config['crypto']
        cfg['basedir'] = self.basedir
        cfg['ca_type'] = self.ca_type
        cfg['name'] = self.name
        cfg['days'] = self.days
        cfg['certsdir'] = self.crtdir

        template_file = '{0}/templates/root.template'.format(self.workspace)
        if not os.path.exists(template_file):
            log.error('{0} not found'.format(template_file))
        template_data = open(template_file, 'r').read()

        template = mako.template.Template(template_data)
        cfg_data = template.render(**cfg)
        open(cfgfile, 'w').write('{0}\n'.format(cfg_data))

    def initca(self, pwfile=None):
        """Empty function to be implemented by subclasses
        """
        log.warning('Feature not implemented')

    @staticmethod
    def updatebundle():
        """Empty function to be implemented by subclass
        """
        log.warning('Feature not implemented')
