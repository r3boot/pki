
import getpass
import jinja2
import os
import time

from pki.logging    import *
from pki.parent     import *

CA_ROOT = 'root'

"""
- One object per CA
- CA structure:
  * basedir/{{name}}/{certs,cfg,csr,db,private}
"""

class CA(Parent):
    ca_type = None

    def __init__(self, config, name=None, days=3652):
        self.cfg = config

        if not self.ca_type:
            error('ca_type not defined')
        if not os.path.exists(self.cfg['ca']['basedir']):
            error('{0} does not exist'.format(self.cfg['ca']['basedir']))

        name = '{0}-{1}'.format(self.cfg['ca']['name'], self.ca_type)
        basedir = '{0}/{1}'.format(self.cfg['ca']['basedir'], name)
        self.ca = {
            'name': name,
            'basedir': basedir,
            'baseurl': '{0}/{1}'.format(self.cfg['ca']['baseurl'], name),
            'cfg': '{0}/cfg/{1}.cfg'.format(basedir, name),
            'csr': '{0}/csr/{1}.csr'.format(basedir, name),
            'crl': '{0}/crl/{1}.crl'.format(basedir, name),
            'key': '{0}/private/{1}.key'.format(basedir, name),
            'crt': '{0}/certs/{1}.pem'.format(basedir, name),
            'days': 60*60*24*days,
            'db': '{0}/db/{1}.db'.format(basedir, name),
            'db_attr': '{0}/db/{1}.db.attr'.format(basedir, name),
            'crt_idx': '{0}/db/{1}-crt.idx'.format(basedir, name),
            'crl_idx': '{0}/db/{1}-crl.idx'.format(basedir, name),
        }
        self.name = name
        self.ca_directories = ['certs', 'cfg', 'crl', 'csr', 'db', 'private']

    def setup(self):
        info('Setup directories for {0} CA'.format(self.ca['name']))

        if os.path.exists(self.ca['basedir']):
            error('{0} already exists'.format(self.ca['basedir']))
        os.mkdir(self.ca['basedir'])

        for directory in self.ca_directories:
            fdir = '{0}/{1}'.format(self.ca['basedir'], directory)
            if not os.path.exists(fdir):
                info('Creating {0}/{1}'.format(self.ca['name'], directory))
                os.mkdir(fdir)

        info('Initialize databases for {0} CA'.format(self.ca['name']))
        for empty_file in [self.ca['db'], self.ca['db_attr']]:
            open(empty_file, 'w').write('')

        for serial_file in [self.ca['crt_idx'], self.ca['crl_idx']]:
            open(serial_file, 'w').write('01\n')

        info('Installing openssl configuration file for {0} CA'.format(self.ca['name']))
        src_template = '{0}/templates/root.cfg.j2'.format(self.cfg['appdir'])
        cfgfile = '{0}/cfg/{1}.cfg'.format(self.ca['basedir'], self.ca['name'])
        if not os.path.exists(src_template):
            error('{0} does not exist'.format(src_template))

        cfg = {}
        cfg['name'] = self.name
        for k,v in self.cfg[self.ca_type].items():
            cfg[k] = v
        for k,v in self.cfg['common'].items():
            cfg[k] = v
        cfg['crypto'] = self.cfg['crypto']
        cfg['basedir'] = self.cfg['ca']['basedir']
        cfg['appdir'] = self.cfg['appdir']

        template_data = open(src_template, 'r').read()
        template = jinja2.Template(template_data)
        cfg_data = template.render(cfg)
        open(cfgfile, 'w').write('{0}\n'.format(cfg_data))

    def initca(self):
        warning('Feature not implemented')

    def updatecrl(self):
        cfg = '{0}/cfg/{1}.cfg'.format(self.ca['basedir'], self.ca['name'])
        crl = '{0}/crl/{1}.crl'.format(self.ca['basedir'], self.ca['name'])

        info('Generating crl for {0} CA'.format(self.ca['name']))
        cmdline = 'openssl ca -gencrl -config {0} -out {1}'.format(self.ca['cfg'], self.ca['crl'])
        os.chdir(self.ca['basedir'])
        proc = self.run(cmdline)
        proc.communicate()


class RootCA(CA):
    ca_type = CA_ROOT

    def __init__(self, config, name=None):
        CA.__init__(self, config, name)

    def initca(self):
        enddate = time.strftime('%Y%m%d%H%M%SZ', time.localtime(time.time() + self.ca['days']))

        info('Generating key and csr for {0} CA'.format(self.ca['name']))
        cmdline = 'openssl req -new -config {0} -out {1} -keyout {2}'.format(
            self.ca['cfg'], self.ca['csr'], self.ca['key'])
        os.chdir(self.ca['basedir'])
        proc = self.run(cmdline)
        proc.communicate()

        info('Generating certificate for {0} CA'.format(self.ca['name']))
        cmdline = 'openssl ca -selfsign -config {0} -in {1} -out {2} -extensions root_ca_ext -enddate {3}'.format(self.ca['cfg'], self.ca['csr'], self.ca['crt'], enddate)
        os.chdir(self.ca['basedir'])
        proc = self.run(cmdline)
        proc.communicate()
