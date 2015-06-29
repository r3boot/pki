
import getpass
import jinja2
import os
import time

from pki.logging    import *
from pki.parent     import *

CA_ROOT = 'root'
CA_INTERMEDIARY = 'intermediary'
CA_AUTOSIGN = 'autosign'

"""
- One object per CA
- CA structure:
  * basedir/{{name}}/{certs,cfg,csr,db,private}
"""

class CA(Parent):
    ca_type = None

    def __init__(self, config, name=None, days=3652):
        self.cfg = config
        if not name:
            name = '{0}-{1}'.format(self.cfg['common']['name'], self.ca_type)

        basedir = os.path.abspath('{0}/{1}'.format(self.cfg['common']['workspace'], name))

        if not self.ca_type:
            error('ca_type not defined')

        self.ca = {
            'name': name,
            'type': self.ca_type,
            'workspace': self.cfg['common']['workspace'],
            'basedir': basedir,
            'baseurl': self.cfg['common']['baseurl'],
            'cfg': '{0}/cfg/{1}.cfg'.format(self.ca['basedir'], name),
            'csr': '{0}/csr/{1}.csr'.format(self.ca['basedir'], name),
            'crl': '{0}/crl/{1}.crl'.format(self.ca['basedir'], name),
            'key': '{0}/private/{1}.key'.format(self.ca['basedir'], name),
            'crt': '{0}/certs/{1}.pem'.format(self.ca['basedir'], name),
            'days': 60*60*24*days,
            'db': '{0}/db/{1}.db'.format(self.ca['basedir'], name),
            'db_attr': '{0}/db/{1}.db.attr'.format(self.ca['basedir'], name),
            'crt_idx': '{0}/db/{1}-crt.idx'.format(self.ca['basedir'], name),
            'crl_idx': '{0}/db/{1}-crl.idx'.format(self.ca['basedir'], name),
        }
        self.name = name
        self.ca_directories = ['certs', 'cfg', 'crl', 'csr', 'db', 'private']

    def gen_enddate(self):
        return time.strftime('%Y%m%d%H%M%SZ', time.localtime(time.time() + self.ca['days']))

    def setup(self, ca_data={}):
        print('\n')
        info('Setup directories for {0} CA'.format(self.ca['name']))
        dump(self.ca)
        dump(self.cfg)

        if os.path.exists(self.ca['basedir']):
            error('{0} already exists'.format(self.ca['basedir']))
        os.mkdir(self.ca['basedir'])

        for directory in self.ca_directories:
            fdir = '{0}/{1}'.format(self.ca['basedir'], directory)
            if not os.path.exists(fdir):
                info('Creating {0}/{1}'.format(self.ca['name'], directory))
                os.mkdir(fdir)

        print('\n')
        info('Initialize databases for {0} CA'.format(self.ca['name']))
        for empty_file in [self.ca['db'], self.ca['db_attr']]:
            open(empty_file, 'w').write('')

        for serial_file in [self.ca['crt_idx'], self.ca['crl_idx']]:
            open(serial_file, 'w').write('01\n')

        print('\n')
        info('Installing openssl configuration file for {0} CA'.format(self.ca['name']))
        src_template = '{0}/templates/root.cfg.j2'.format(self.ca['workspace'])
        cfgfile = '{0}/cfg/{1}.cfg'.format(self.ca['basedir'], self.ca['name'])
        if not os.path.exists(src_template):
            error('{0} does not exist'.format(src_template))

        cfg = {}
        for k,v in self.cfg['common'].items():
            cfg[k] = v

        if self.ca_type in [CA_AUTOSIGN]:
            for k,v in ca_data.items():
                cfg[k] = v
        else:
            for k,v in self.cfg[self.ca_type].items():
                cfg[k] = v


        cfg['crypto'] = self.cfg['crypto']
        cfg['basedir'] = '{0}/{1}'.format(self.ca['workspace'], self.name)
        cfg['ca_type'] = self.ca_type
        cfg['name'] = self.name

        template_data = open(src_template, 'r').read()
        template = jinja2.Template(template_data)
        cfg_data = template.render(cfg)
        open(cfgfile, 'w').write('{0}\n'.format(cfg_data))

    def initca(self):
        warning('Feature not implemented')

    def updatecrl(self):
        cfg = '{0}/cfg/{1}.cfg'.format(self.ca['basedir'], self.ca['name'])
        crl = '{0}/crl/{1}.crl'.format(self.ca['basedir'], self.ca['name'])

        print('\n')
        info('Generating crl for {0} CA'.format(self.ca['name']))
        cmdline = 'openssl ca -gencrl -config {0} -out {1}'.format(self.ca['cfg'], self.ca['crl'])
        os.chdir(self.ca['basedir'])
        proc = self.run(cmdline, stdout=True)
        proc.communicate()

    def sign_intermediary(self, csr, crt):
        print('\n')
        info('Signing certificate using {0} CA'.format(self.ca['name']))
        cmdline = 'openssl ca -config {0} -in {1} -out {2} -extensions intermediate_ca_ext -enddate {3}'.format(self.ca['cfg'], csr, crt, self.gen_enddate())
        os.chdir(self.ca['basedir'])
        proc = self.run(cmdline, stdout=True)
        proc.communicate()

    def autosign(self, csr, crt):
        info('Signing certificate using {0} CA'.format(self.ca['name']))
        cmdline = 'openssl ca -config {0} -in {1} -out {2} -extensions server_ext'.format(self.ca['cfg'], csr, crt)
        os.chdir(self.ca['basedir'])
        proc = self.run(cmdline, stdin=True)
        proc.communicate(input=b'y\ny\n')

class RootCA(CA):
    ca_type = CA_ROOT

    def __init__(self, config):
        CA.__init__(self, config)

    def initca(self):
        print('\n')
        info('Generating key and csr for {0} CA'.format(self.ca['name']))
        cmdline = 'openssl req -new -config {0} -out {1} -keyout {2}'.format(
            self.ca['cfg'], self.ca['csr'], self.ca['key'])
        os.chdir(self.ca['basedir'])
        proc = self.run(cmdline, stdout=True)
        proc.communicate()

        print('\n')
        info('Generating certificate for {0} CA'.format(self.ca['name']))
        cmdline = 'openssl ca -selfsign -config {0} -in {1} -out {2} -extensions root_ca_ext -enddate {3}'.format(self.ca['cfg'], self.ca['csr'], self.ca['crt'], self.gen_enddate())
        os.chdir(self.ca['basedir'])
        proc = self.run(cmdline, stdout=True)
        proc.communicate()


class IntermediaryCA(CA):
    ca_type = CA_INTERMEDIARY

    def __init__(self, config):
        CA.__init__(self, config)

    def initca(self, parent=None):
        if not parent:
            error('initca needs a parent CA')
        print('\n')
        info('Generating key and csr for {0} CA'.format(self.ca['name']))
        cmdline = 'openssl req -new -config {0} -out {1} -keyout {2}'.format(
            self.ca['cfg'], self.ca['csr'], self.ca['key'])
        os.chdir(self.ca['basedir'])
        proc = self.run(cmdline, stdout=True)
        proc.communicate()

        print('\n')
        info('Generating certificate for {0} CA'.format(self.ca['name']))
        parent.sign_intermediary(self.ca['csr'], self.ca['crt'])


class AutosignCA(CA):
    ca_type = CA_AUTOSIGN

    def __init__(self, config, name=None):
        if not name:
            error('No name supplied to class')
        CA.__init__(self, config, name=name)

    def initca(self, parent=None):
        if not parent:
            error('initca needs a parent CA')
        print('\n')
        info('Generating key and csr for {0} CA'.format(self.ca['name']))
        cmdline = 'openssl req -new -config {0} -out {1} -keyout {2}'.format(
            self.ca['cfg'], self.ca['csr'], self.ca['key'])
        os.chdir(self.ca['basedir'])
        proc = self.run(cmdline, stdout=True)
        proc.communicate()

        print('\n')
        info('Generating certificate for {0} CA'.format(self.ca['name']))
        parent.sign_intermediary(self.ca['csr'], self.ca['crt'])
