class CA:
    """ CA:     Class representing a Certificate Authority
    """
    ca_type = None
    ca = {}

    def __init__(self, config):
        """ __init__:   Initializes CA class

        @param:     config  Dictionary containing the contents of the
                            configuration file
        """
        self.cfg = config
        name = '{0}-{1}'.format(self.cfg['common']['name'], self.ca_type)
        basedir = '{0}/{1}'.format(self.cfg['common']['workspace'], name)

        if not self.ca_type:
            error('ca_type not defined')

        days = 60*60*365*10
        try:
            days = self.cfg[self.ca_type]['days']
        except KeyError:
            days = self.cfg['common']['days']

        self.ca = {
            'name': name,
            'type': self.ca_type,
            'workspace': self.cfg['common']['workspace'],
            'basedir': basedir,
            'baseurl': self.cfg['common']['baseurl'],
            'cfg': fpath('{0}/cfg/{1}.cfg'.format(basedir, name)),
            'csr': fpath('{0}/csr/{1}.csr'.format(basedir, name)),
            'crl': fpath('{0}/crl/{1}.crl'.format(basedir, name)),
            'key': fpath('{0}/private/{1}.key'.format(basedir, name)),
            'crt': fpath('{0}/certs/{1}.pem'.format(basedir, name)),
            'bundle': fpath('{0}/certs/{1}-bundle.pem'.format(basedir, name)),
            'days': days,
            'db': fpath('{0}/db/{1}.db'.format(basedir, name)),
            'db_attr': fpath('{0}/db/{1}-db.attr'.format(basedir, name)),
            'crt_idx': fpath('{0}/db/{1}-crt.idx'.format(basedir, name)),
            'crl_idx': fpath('{0}/db/{1}-crl.idx'.format(basedir, name)),
        }
        self.name = name
        self.basedir = os.path.abspath(basedir)
        self.ca_directories = ['certs', 'cfg', 'crl', 'csr', 'db', 'private']

    def gen_enddate(self):
        """ gen_enddate:    Helper function to generate an enddate timestamp

        @returns:   str String containing the timestamp
        """
        days_s = self.ca['days'] * (60*60*24)
        future_date = time.localtime(time.time() + days_s)
        return time.strftime('%Y%m%d%H%M%SZ', future_date)

    def setup(self):
        """ setup:  Initialize the file structure for this CA
        """
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

        info('Installing openssl configuration file for {0} CA'.format(
            self.ca['name']
        ))
        cfgfile = '{0}/cfg/{1}.cfg'.format(self.ca['basedir'], self.ca['name'])

        cfg = {}
        cfg.update(self.cfg['common'])

        cfg.update(self.cfg[self.ca_type])

        cfg['crypto'] = self.cfg['crypto']
        cfg['basedir'] = '{0}/{1}'.format(self.ca['workspace'], self.name)
        cfg['ca_type'] = self.ca_type
        cfg['name'] = self.name
        cfg['ca'] = self.ca

        template = mako.template.Template(root_ca_template)
        cfg_data = template.render(**cfg)
        open(cfgfile, 'w').write('{0}\n'.format(cfg_data))

    def initca(self):
        """ initca      Empty function to be implemented by subclasses
        """
        warning('Feature not implemented')

    def updatebundle(self):
        """ updatebundle:   Update the certificate bundle for this CA
        """
        warning('Feature not implemented')

    def updatecrl(self, pwfile):
        """ updatecrl   Update the Certificate Revocation List for this CA
        """
        info('Generating crl for {0} CA'.format(self.ca['name']))
        cmdline = 'openssl ca -gencrl -config {0} -out {1}'.format(
            fpath(self.ca['cfg']),
            fpath(self.ca['crl']),
        )
        if pwfile:
            cmdline += ' -passin file:{0}'.format(pwfile)
        os.chdir(self.basedir)
        proc = run(cmdline)
        proc.communicate()

    def sign_intermediary(self, csr, crt, pwfile):
        """ sign_intermediary:  Perform a intermediary certificate signing

        @param:     csr Path to the Certificate Signing Request
        @param:     crt Path to the output certificate
        """
        info('Signing certificate using {0} CA'.format(self.ca['name']))
        cmdline = 'openssl ca -config {0} -in {1} -out {2} -batch'.format(
            fpath(self.ca['cfg']),
            fpath(csr),
            fpath(crt),
        )
        cmdline += ' -passin file:{0}'.format(pwfile)
        cmdline += ' -extensions intermediate_ca_ext -enddate {0}'.format(
            self.gen_enddate()
        )
        os.chdir(self.basedir)
        proc = run(cmdline, stdout=True)
        proc.communicate()

