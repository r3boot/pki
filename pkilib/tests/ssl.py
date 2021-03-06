import glob
import nose
import os
import shutil

# TODO: check for Country == 2 chars

import yaml

import pkilib.log as log
import pkilib.ssl as ssl

CFG_FILE = './workspace/unittest/config/pki.yml'
LOG_CFG = './workspace/unittest/config/logging.yml'
LOG_HANDLER = 'unittest'

ROOT_TEMPLATE = './workspace/templates/root.template'
ROOT_NAME = 'test-root'
ROOT_BASEDIR = './workspace/{0}'.format(ROOT_NAME)
ROOT_CERTS = '{0}/certs'.format(ROOT_BASEDIR)
ROOT_CFG = '{0}/cfg/{1}.cfg'.format(ROOT_BASEDIR, ROOT_NAME)
ROOT_KEY = '{0}/private/{1}.key'.format(ROOT_BASEDIR, ROOT_NAME)
ROOT_CSR = '{0}/csr/{1}.csr'.format(ROOT_BASEDIR, ROOT_NAME)
ROOT_CRT = '{0}/certs/{1}.pem'.format(ROOT_BASEDIR, ROOT_NAME)
ROOT_BUNDLE = '{0}/certs/{1}-bundle.pem'.format(ROOT_BASEDIR, ROOT_NAME)
ROOT_CRL = '{0}/crl/{1}.crl'.format(ROOT_BASEDIR, ROOT_NAME)
ROOT_DB = '{0}/db/{1}.db'.format(ROOT_BASEDIR, ROOT_NAME)
ROOT_EXT = 'root_ca_ext'

INTERMEDIARY_NAME = 'test-intermediary'
INTERMEDIARY_BASEDIR = './workspace/{0}'.format(INTERMEDIARY_NAME)
INTERMEDIARY_CFG = '{0}/cfg/{1}.cfg'.format(
    INTERMEDIARY_BASEDIR,
    INTERMEDIARY_NAME
)
INTERMEDIARY_CSR = '{0}/csr/{1}.csr'.format(
    INTERMEDIARY_BASEDIR,
    INTERMEDIARY_NAME
)
INTERMEDIARY_CRT = '{0}/certs/{1}.pem'.format(
    INTERMEDIARY_BASEDIR,
    INTERMEDIARY_NAME
)
INTERMEDIARY_CRL = '{0}/crl/{1}.crl'.format(
    INTERMEDIARY_BASEDIR,
    INTERMEDIARY_NAME
)

AUTOSIGN_NAME = 'test-autosign'
AUTOSIGN_BASEDIR = './workspace/{0}'.format(AUTOSIGN_NAME)
AUTOSIGN_CFG = '{0}/cfg/{1}.cfg'.format(AUTOSIGN_BASEDIR, AUTOSIGN_NAME)
AUTOSIGN_KEY = '{0}/private/{1}.key'.format(AUTOSIGN_BASEDIR, AUTOSIGN_NAME)
AUTOSIGN_CSR = '{0}/csr/{1}.csr'.format(AUTOSIGN_BASEDIR, AUTOSIGN_NAME)
AUTOSIGN_CRT = '{0}/certs/{1}.pem'.format(AUTOSIGN_BASEDIR, AUTOSIGN_NAME)
AUTOSIGN_CRL = '{0}/crl/{1}.crl'.format(AUTOSIGN_BASEDIR, AUTOSIGN_NAME)
AUTOSIGN_DB = '{0}/db/{1}.db'.format(AUTOSIGN_BASEDIR, AUTOSIGN_NAME)
AUTOSIGN_EXT = 'server_ext'
PWFILE = './workspace/pwfile.input'

TLS_NAME = 'test.host.name'
TLS_CFG = '{0}/cfg/{1}.cfg'.format(AUTOSIGN_BASEDIR, TLS_NAME)
TLS_CSR = '{0}/csr/{1}.csr'.format(AUTOSIGN_BASEDIR, TLS_NAME)
TLS_CRT = '{0}/certs/{1}.pem'.format(AUTOSIGN_BASEDIR, TLS_NAME)
TLS_TEMPLATE = './workspace/templates/tls_server.template'


class test_OpenSSL_class_creation:
    def setUp(self):
        log.LOGGER = log.get_handler(LOG_CFG, LOG_HANDLER)
        self.config = yaml.load(open(CFG_FILE, 'r').read())

    @nose.tools.raises(SystemExit)
    def test_invalid_ca_type(self):
        assert ssl.OpenSSL({}, 'somerandomcatype') is None

    def test_filled_ca_data(self):
        ca = ssl.OpenSSL(self.config, ssl.CA_ROOT)
        assert len(ca.ca_data) > 0


class test_OpenSSL_setup_ca_structure:
    def setUp(self):
        log.LOGGER = log.get_handler(LOG_CFG, LOG_HANDLER)
        config = yaml.load(open(CFG_FILE, 'r').read())
        self.ca = ssl.OpenSSL(config, ssl.CA_ROOT)

    def tearDown(self):
        if os.path.exists(ROOT_BASEDIR):
            shutil.rmtree(ROOT_BASEDIR)

    def test_existing_basedir(self):
        os.mkdir(self.ca.ca_data['basedir'])
        assert self.ca.setup_ca_structure() is False
        os.rmdir(self.ca.ca_data['basedir'])

    def test_nonexisting_template(self):
        tmp_cfg = '{0}.temp'.format(ROOT_TEMPLATE)
        shutil.move(ROOT_TEMPLATE, tmp_cfg)
        assert self.ca.setup_ca_structure() is False
        shutil.move(tmp_cfg, ROOT_TEMPLATE)

    def test_structure_created(self):
        basedir = self.ca.ca_data['basedir']
        cfg = '{0}/cfg/{1}.cfg'.format(basedir, self.ca.ca_data['name'])
        ca_dirs = ['certs', 'cfg', 'crl', 'csr', 'db', 'private']
        assert self.ca.setup_ca_structure() is True
        assert os.path.exists(self.ca.ca_data['basedir']) is True
        for DIR in ca_dirs:
            dest_dir = '{0}/{1}'.format(basedir, DIR)
            assert os.path.exists(dest_dir) is True
        assert os.path.exists(cfg) is True

    def test_incomplete_template(self):
        old_cn = self.ca.ca_data['cn']
        del(self.ca.ca_data['cn'])
        assert self.ca.setup_ca_structure() is False
        self.ca.ca_data['cn'] = old_cn


class test_OpenSSL_genkey_exceptions:
    def setUp(self):
        log.LOGGER = log.get_handler(LOG_CFG, LOG_HANDLER)
        config = yaml.load(open(CFG_FILE, 'r').read())
        open(PWFILE, 'w').write('{0}\n'.format(ROOT_NAME))
        self.ca = ssl.OpenSSL(config, ssl.CA_ROOT)
        assert self.ca.setup_ca_structure() is True
        open(ROOT_CFG, 'w').write(ROOT_NAME)

    def tearDown(self):
        if os.path.exists(ROOT_BASEDIR):
            shutil.rmtree(ROOT_BASEDIR)
        if os.path.exists(PWFILE):
            os.unlink(PWFILE)

    def test_no_configuration(self):
        tmp_cfg = '{0}.temp'.format(ROOT_CFG)
        shutil.move(ROOT_CFG, tmp_cfg)
        assert self.ca.genkey(ROOT_CFG, ROOT_NAME, pwfile=PWFILE) is False
        shutil.move(tmp_cfg, ROOT_CFG)

    def test_existing_key(self):
        open(ROOT_KEY, 'w').write(ROOT_NAME)
        assert self.ca.genkey(ROOT_CFG, ROOT_NAME, pwfile=PWFILE) is False
        os.unlink(ROOT_KEY)

    def test_existing_csr(self):
        open(ROOT_CSR, 'w').write(ROOT_NAME)
        assert self.ca.genkey(ROOT_CFG, ROOT_NAME, pwfile=PWFILE) is False
        os.unlink(ROOT_CSR)

    def test_undefined_pwfile(self):
        assert self.ca.genkey(ROOT_CFG, ROOT_NAME, pwfile=None) is False

    def test_nonexisting_pwfile(self):
        os.unlink(PWFILE)
        assert self.ca.genkey(ROOT_CFG, ROOT_NAME, pwfile=PWFILE) is False


class test_OpenSSL_genkey:
    def setUp(self):
        log.LOGGER = log.get_handler(LOG_CFG, LOG_HANDLER)
        self.config = yaml.load(open(CFG_FILE, 'r').read())
        open(PWFILE, 'w').write('{0}\n'.format(ROOT_NAME))
        self.ca = ssl.OpenSSL(self.config, ssl.CA_ROOT)
        if os.path.exists(ROOT_BASEDIR):
            shutil.rmtree(ROOT_BASEDIR)
        assert self.ca.setup_ca_structure() is True

    def tearDown(self):
        if os.path.exists(ROOT_BASEDIR):
            shutil.rmtree(ROOT_BASEDIR)
        if os.path.exists(AUTOSIGN_BASEDIR):
            shutil.rmtree(AUTOSIGN_BASEDIR)
        if os.path.exists(PWFILE):
            os.unlink(PWFILE)

    def test_generates_files(self):
        assert self.ca.genkey(ROOT_CFG, ROOT_NAME, pwfile=PWFILE) is True
        assert os.path.exists(ROOT_KEY) is True
        assert os.path.exists(ROOT_CSR) is True

    def test_autosign_generates_files(self):
        autosign = ssl.OpenSSL(self.config, ssl.CA_AUTOSIGN)
        assert autosign.setup_ca_structure() is True
        assert autosign.genkey(AUTOSIGN_CFG, AUTOSIGN_NAME) is True


class test_OpenSSL_selfsign_exceptions:
    def setUp(self):
        log.LOGGER = log.get_handler(LOG_CFG, LOG_HANDLER)
        self.config = yaml.load(open(CFG_FILE, 'r').read())
        open(PWFILE, 'w').write('{0}\n'.format(ROOT_NAME))
        self.ca = ssl.OpenSSL(self.config, ssl.CA_ROOT)
        if os.path.exists(ROOT_BASEDIR):
            shutil.rmtree(ROOT_BASEDIR)
        assert self.ca.setup_ca_structure() is True
        open(ROOT_CSR, 'w').write(ROOT_NAME)
        open(ROOT_CFG, 'w').write(ROOT_NAME)
        open(ROOT_CRT, 'w').write(ROOT_NAME)

    def tearDown(self):
        if os.path.exists(ROOT_BASEDIR):
            shutil.rmtree(ROOT_BASEDIR)
        os.unlink(PWFILE)

    def test_no_configuration(self):
        tmp_cfg = '{0}.temp'.format(ROOT_CFG)
        shutil.move(ROOT_CFG, tmp_cfg)
        assert self.ca.selfsign(ROOT_NAME, pwfile=PWFILE) is False
        shutil.move(tmp_cfg, ROOT_CFG)

    def test_undefined_pwfile(self):
        assert self.ca.selfsign(ROOT_NAME, pwfile=None) is False

    def test_nonexisting_pwfile(self):
        tmp_pwfile = '{0}.temp'.format(PWFILE)
        shutil.move(PWFILE, tmp_pwfile)
        assert self.ca.selfsign(ROOT_NAME, pwfile=PWFILE) is False
        shutil.move(tmp_pwfile, PWFILE)

    def test_no_csr(self):
        tmp_csr = '{0}.temp'.format(ROOT_CSR)
        shutil.move(ROOT_CSR, tmp_csr)
        assert self.ca.selfsign(ROOT_NAME, pwfile=PWFILE) is False
        shutil.move(tmp_csr, ROOT_CSR)

    def test_existing_crt(self):
        open(ROOT_CRT, 'w').write(ROOT_NAME)
        assert self.ca.selfsign(ROOT_NAME, pwfile=PWFILE) is False
        os.unlink(ROOT_CRT)

    def test_invalid_ca_type(self):
        autosign = ssl.OpenSSL(self.config, ssl.CA_AUTOSIGN)
        assert autosign.selfsign(AUTOSIGN_NAME, AUTOSIGN_EXT) is False


class test_OpenSSL_selfsign:
    def setUp(self):
        log.LOGGER = log.get_handler(LOG_CFG, LOG_HANDLER)
        config = yaml.load(open(CFG_FILE, 'r').read())
        open(PWFILE, 'w').write('{0}\n'.format(ROOT_NAME))
        self.ca = ssl.OpenSSL(config, ssl.CA_ROOT)
        if os.path.exists(ROOT_BASEDIR):
            shutil.rmtree(ROOT_BASEDIR)
        assert self.ca.setup_ca_structure() is True
        assert self.ca.genkey(ROOT_CFG, ROOT_NAME, pwfile=PWFILE) is True

    def tearDown(self):
        if os.path.exists(ROOT_BASEDIR):
            shutil.rmtree(ROOT_BASEDIR)
        os.unlink(PWFILE)

    def test_generates_files(self):
        assert self.ca.selfsign(ROOT_NAME, pwfile=PWFILE) is True
        assert os.path.exists(ROOT_CRT) is True


class test_OpenSSL_updatecrl_exceptions:
    def setUp(self):
        log.LOGGER = log.get_handler(LOG_CFG, LOG_HANDLER)
        self.config = yaml.load(open(CFG_FILE, 'r').read())
        open(PWFILE, 'w').write('{0}\n'.format(ROOT_NAME))
        self.ca = ssl.OpenSSL(self.config, ssl.CA_ROOT)
        if os.path.exists(ROOT_BASEDIR):
            shutil.rmtree(ROOT_BASEDIR)
        assert self.ca.setup_ca_structure() is True
        open(ROOT_CFG, 'w').write(ROOT_NAME)

    def tearDown(self):
        if os.path.exists(ROOT_BASEDIR):
            shutil.rmtree(ROOT_BASEDIR)
        os.unlink(PWFILE)

    def test_undefined_pwfile(self):
        assert self.ca.updatecrl(pwfile=None) is False

    def test_nonexisting_pwfile(self):
        tmp_pwfile = '{0}.temp'.format(PWFILE)
        shutil.move(PWFILE, tmp_pwfile)
        assert self.ca.updatecrl(pwfile=PWFILE) is False
        shutil.move(tmp_pwfile, PWFILE)

    def test_no_configuration(self):
        tmp_cfg = '{0}.temp'.format(ROOT_CFG)
        shutil.move(ROOT_CFG, tmp_cfg)
        assert self.ca.updatecrl(pwfile=PWFILE) is False
        shutil.move(tmp_cfg, ROOT_CFG)


class test_OpenSSL_updatecrl:
    def setUp(self):
        log.LOGGER = log.get_handler(LOG_CFG, LOG_HANDLER)
        self.config = yaml.load(open(CFG_FILE, 'r').read())
        open(PWFILE, 'w').write('{0}\n'.format(ROOT_NAME))
        self.ca = ssl.OpenSSL(self.config, ssl.CA_ROOT)
        if os.path.exists(ROOT_BASEDIR):
            shutil.rmtree(ROOT_BASEDIR)
        if os.path.exists(INTERMEDIARY_BASEDIR):
            shutil.rmtree(INTERMEDIARY_BASEDIR)
        if os.path.exists(AUTOSIGN_BASEDIR):
            shutil.rmtree(AUTOSIGN_BASEDIR)
        assert self.ca.setup_ca_structure() is True
        assert self.ca.genkey(ROOT_CFG, ROOT_NAME, pwfile=PWFILE) is True
        assert self.ca.selfsign(ROOT_NAME, pwfile=PWFILE) is True

    def tearDown(self):
        if os.path.exists(ROOT_BASEDIR):
            shutil.rmtree(ROOT_BASEDIR)
        if os.path.exists(INTERMEDIARY_BASEDIR):
            shutil.rmtree(INTERMEDIARY_BASEDIR)
        if os.path.exists(AUTOSIGN_BASEDIR):
            shutil.rmtree(AUTOSIGN_BASEDIR)
        os.unlink(PWFILE)

    def test_generates_files(self):
        if os.path.exists(ROOT_CRL):
            os.unlink(ROOT_CRL)
        assert self.ca.updatecrl(pwfile=PWFILE) is True

    def test_intermediary_generates_files(self):
        inter = ssl.OpenSSL(self.config, ssl.CA_INTERMEDIARY)
        cfg = INTERMEDIARY_CFG
        name = INTERMEDIARY_NAME
        csr = INTERMEDIARY_CSR
        crt = INTERMEDIARY_CRT
        assert inter.setup_ca_structure() is True
        assert inter.genkey(cfg, name, pwfile=PWFILE) is True
        assert self.ca.sign_intermediary(csr, crt, PWFILE, 1) is True
        if os.path.exists(INTERMEDIARY_CRL):
            os.unlink(INTERMEDIARY_CRL)
        assert inter.updatecrl(pwfile=PWFILE) is True

    def test_autosign_generates_files(self):
        inter = ssl.OpenSSL(self.config, ssl.CA_INTERMEDIARY)
        cfg = INTERMEDIARY_CFG
        name = INTERMEDIARY_NAME
        csr = INTERMEDIARY_CSR
        crt = INTERMEDIARY_CRT
        assert inter.setup_ca_structure() is True
        assert inter.genkey(cfg, name, pwfile=PWFILE) is True
        assert self.ca.sign_intermediary(csr, crt, PWFILE, 1) is True

        autosign = ssl.OpenSSL(self.config, ssl.CA_AUTOSIGN)
        cfg = AUTOSIGN_CFG
        name = AUTOSIGN_NAME
        csr = AUTOSIGN_CSR
        crt = AUTOSIGN_CRT
        assert autosign.setup_ca_structure() is True
        assert autosign.genkey(cfg, name) is True
        assert inter.sign_intermediary(csr, crt, PWFILE, 1) is True

        if os.path.exists(AUTOSIGN_CRL):
            os.unlink(AUTOSIGN_CRL)
        assert autosign.updatecrl() is True


class test_OpenSSL_sign_intermediary_exceptions:
    def setUp(self):
        log.LOGGER = log.get_handler(LOG_CFG, LOG_HANDLER)
        config = yaml.load(open(CFG_FILE, 'r').read())
        open(PWFILE, 'w').write('{0}\n'.format(ROOT_NAME))

        if os.path.exists(ROOT_BASEDIR):
            shutil.rmtree(ROOT_BASEDIR)
        if os.path.exists(INTERMEDIARY_BASEDIR):
            shutil.rmtree(INTERMEDIARY_BASEDIR)

        self.root = ssl.OpenSSL(config, ssl.CA_ROOT)
        assert self.root.setup_ca_structure() is True

        self.inter = ssl.OpenSSL(config, ssl.CA_INTERMEDIARY)
        assert self.inter.setup_ca_structure() is True

        open(ROOT_CFG, 'w').write(ROOT_NAME)
        open(INTERMEDIARY_CFG, 'w').write(INTERMEDIARY_NAME)
        open(INTERMEDIARY_CSR, 'w').write(INTERMEDIARY_NAME)

    def tearDown(self):
        if os.path.exists(ROOT_BASEDIR):
            shutil.rmtree(ROOT_BASEDIR)
        if os.path.exists(INTERMEDIARY_BASEDIR):
            shutil.rmtree(INTERMEDIARY_BASEDIR)
        if os.path.exists(PWFILE):
            os.unlink(PWFILE)

    def test_no_cfg(self):
        cfg = self.root.ca_data['cfg']
        csr = self.inter.ca_data['csr']
        crt = self.inter.ca_data['crt']
        days = self.inter.ca_data['days']
        tmp_cfg = '{0}.temp'.format(cfg)
        shutil.move(cfg, tmp_cfg)
        assert self.root.sign_intermediary(csr, crt, PWFILE, days) is False
        shutil.move(tmp_cfg, cfg)

    def test_no_csr(self):
        csr = self.inter.ca_data['csr']
        crt = self.inter.ca_data['crt']
        days = self.inter.ca_data['days']
        tmp_csr = '{0}.temp'.format(csr)
        shutil.move(csr, tmp_csr)
        assert self.root.sign_intermediary(csr, crt, PWFILE, days) is False
        shutil.move(tmp_csr, csr)

    def test_existing_crt(self):
        csr = self.inter.ca_data['csr']
        crt = self.inter.ca_data['crt']
        days = self.inter.ca_data['days']
        open(crt, 'w').write(INTERMEDIARY_NAME)
        assert self.root.sign_intermediary(csr, crt, PWFILE, days) is False
        os.unlink(crt)

    def test_nonexisting_pwfile(self):
        csr = self.inter.ca_data['csr']
        crt = self.inter.ca_data['crt']
        days = self.inter.ca_data['days']
        tmp_pwfile = '{0}.temp'.format(PWFILE)
        shutil.move(PWFILE, tmp_pwfile)
        assert self.root.sign_intermediary(csr, crt, PWFILE, days) is False
        shutil.move(tmp_pwfile, PWFILE)

    def test_nonint_days(self):
        csr = self.inter.ca_data['csr']
        crt = self.inter.ca_data['crt']
        days = 'invalidvalue'
        assert self.root.sign_intermediary(csr, crt, PWFILE, days) is False


class test_OpenSSL_sign_intermediary:
    def setUp(self):
        log.LOGGER = log.get_handler(LOG_CFG, LOG_HANDLER)
        config = yaml.load(open(CFG_FILE, 'r').read())
        open(PWFILE, 'w').write('{0}\n'.format(ROOT_NAME))

        if os.path.exists(ROOT_BASEDIR):
            shutil.rmtree(ROOT_BASEDIR)
        if os.path.exists(INTERMEDIARY_BASEDIR):
            shutil.rmtree(INTERMEDIARY_BASEDIR)

        self.root = ssl.OpenSSL(config, ssl.CA_ROOT)
        assert self.root.setup_ca_structure() is True
        assert self.root.genkey(ROOT_CFG, ROOT_NAME, pwfile=PWFILE) is True
        assert self.root.selfsign(ROOT_NAME, pwfile=PWFILE) is True

        self.inter = ssl.OpenSSL(config, ssl.CA_INTERMEDIARY)
        cfg = INTERMEDIARY_CFG
        name = INTERMEDIARY_NAME
        assert self.inter.setup_ca_structure() is True
        assert self.inter.genkey(cfg, name, pwfile=PWFILE) is True

    def tearDown(self):
        if os.path.exists(ROOT_BASEDIR):
            shutil.rmtree(ROOT_BASEDIR)
        if os.path.exists(INTERMEDIARY_BASEDIR):
            shutil.rmtree(INTERMEDIARY_BASEDIR)
        if os.path.exists(PWFILE):
            os.unlink(PWFILE)

    def test_generates_files(self):
        csr = self.inter.ca_data['csr']
        crt = self.inter.ca_data['crt']
        days = self.inter.ca_data['days']
        assert self.root.sign_intermediary(csr, crt, PWFILE, days) is True


class test_OpenSSL_sign_exceptions:
    def setUp(self):
        log.LOGGER = log.get_handler(LOG_CFG, LOG_HANDLER)
        config = yaml.load(open(CFG_FILE, 'r').read())
        open(PWFILE, 'w').write('{0}\n'.format(ROOT_NAME))

        if os.path.exists(AUTOSIGN_BASEDIR):
            shutil.rmtree(AUTOSIGN_BASEDIR)

        self.ca = ssl.OpenSSL(config, ssl.CA_AUTOSIGN)
        assert self.ca.setup_ca_structure() is True
        open(AUTOSIGN_CFG, 'w').write(AUTOSIGN_NAME)
        open(AUTOSIGN_CSR, 'w').write(AUTOSIGN_NAME)

    def tearDown(self):
        if os.path.exists(AUTOSIGN_BASEDIR):
            shutil.rmtree(AUTOSIGN_BASEDIR)
        if os.path.exists(PWFILE):
            os.unlink(PWFILE)

    def test_undefined_name(self):
        assert self.ca.sign(None) is False

    def test_empty_name(self):
        assert self.ca.sign('') is False

    def test_nonexisting_cfg(self):
        tmp_cfg = '{0}.temp'.format(AUTOSIGN_CFG)
        shutil.move(AUTOSIGN_CFG, tmp_cfg)
        assert self.ca.sign(TLS_NAME) is False
        shutil.move(tmp_cfg, AUTOSIGN_CFG)

    def test_nonexisting_csr(self):
        tmp_csr = '{0}'.format(AUTOSIGN_CSR)
        shutil.move(AUTOSIGN_CSR, tmp_csr)
        assert self.ca.sign(TLS_NAME) is False
        shutil.move(tmp_csr, AUTOSIGN_CSR)

    def test_existing_crt(self):
        open(TLS_CFG, 'w').write(TLS_NAME)
        open(TLS_CSR, 'w').write(TLS_NAME)
        open(TLS_CRT, 'w').write(TLS_NAME)
        assert self.ca.sign(TLS_NAME) is False
        os.unlink(TLS_CRT)
        os.unlink(TLS_CSR)
        os.unlink(TLS_CFG)


class test_OpenSSL_sign:
    def setUp(self):
        log.LOGGER = log.get_handler(LOG_CFG, LOG_HANDLER)
        config = yaml.load(open(CFG_FILE, 'r').read())
        open(PWFILE, 'w').write('{0}\n'.format(ROOT_NAME))

        if os.path.exists(ROOT_BASEDIR):
            shutil.rmtree(ROOT_BASEDIR)
        if os.path.exists(INTERMEDIARY_BASEDIR):
            shutil.rmtree(INTERMEDIARY_BASEDIR)
        if os.path.exists(AUTOSIGN_BASEDIR):
            shutil.rmtree(AUTOSIGN_BASEDIR)

        self.root = ssl.OpenSSL(config, ssl.CA_ROOT)
        cfg = self.root.ca_data['cfg']
        name = self.root.ca_data['name']
        assert self.root.setup_ca_structure() is True
        assert self.root.genkey(cfg, name, pwfile=PWFILE) is True
        assert self.root.selfsign(name, pwfile=PWFILE) is True

        self.inter = ssl.OpenSSL(config, ssl.CA_INTERMEDIARY)
        cfg = INTERMEDIARY_CFG
        name = INTERMEDIARY_NAME
        csr = INTERMEDIARY_CSR
        crt = INTERMEDIARY_CRT
        assert self.inter.setup_ca_structure() is True
        assert self.inter.genkey(cfg, name, pwfile=PWFILE) is True
        assert self.root.sign_intermediary(csr, crt, PWFILE, 1) is True

        self.ca = ssl.OpenSSL(config, ssl.CA_AUTOSIGN)
        cfg = AUTOSIGN_CFG
        name = AUTOSIGN_NAME
        csr = AUTOSIGN_CSR
        crt = AUTOSIGN_CRT
        assert self.ca.setup_ca_structure() is True
        assert self.ca.genkey(cfg, name, pwfile=PWFILE) is True
        assert self.inter.sign_intermediary(csr, crt, PWFILE, 1) is True

        cfg_data = self.ca.gen_server_cfg(TLS_NAME)
        assert cfg_data is not False
        open(TLS_CFG, 'w').write(cfg_data)
        assert self.ca.genkey(TLS_CFG, TLS_NAME, pwfile=PWFILE) is True

    def tearDown(self):
        if os.path.exists(ROOT_BASEDIR):
            shutil.rmtree(ROOT_BASEDIR)
        if os.path.exists(INTERMEDIARY_BASEDIR):
            shutil.rmtree(INTERMEDIARY_BASEDIR)
        if os.path.exists(AUTOSIGN_BASEDIR):
            shutil.rmtree(AUTOSIGN_BASEDIR)
        if os.path.exists(PWFILE):
            os.unlink(PWFILE)

    def test_generates_files(self):
        assert self.ca.sign(TLS_NAME) is True


class test_OpenSSL_gen_server_cfg:
    def setUp(self):
        log.LOGGER = log.get_handler(LOG_CFG, LOG_HANDLER)
        config = yaml.load(open(CFG_FILE, 'r').read())
        self.ca = ssl.OpenSSL(config, ssl.CA_ROOT)

    def test_nonexisting_template(self):
        tmp_cfg = '{0}.temp'.format(TLS_TEMPLATE)
        shutil.move(TLS_TEMPLATE, tmp_cfg)
        assert self.ca.gen_server_cfg(TLS_NAME) is False
        shutil.move(tmp_cfg, TLS_TEMPLATE)

    def test_incomplete_template(self):
        old_country = self.ca.ca_data['country']
        del(self.ca.ca_data['country'])
        assert self.ca.gen_server_cfg(TLS_NAME) is False
        self.ca.ca_data['country'] = old_country

    def test_undefined_fqdn(self):
        assert self.ca.gen_server_cfg(None) is False

    def test_empty_fqdn(self):
        assert self.ca.gen_server_cfg('') is False

    def test_1level(self):
        assert self.ca.gen_server_cfg('some') is False

    def test_2level(self):
        assert self.ca.gen_server_cfg('some.host') != False

    def test_3level(self):
        assert self.ca.gen_server_cfg('some.host.name') != False

    def test_4level(self):
        assert self.ca.gen_server_cfg('some.invalid.host.name') is False


class test_OpenSSL_updatebundle:
    def setUp(self):
        log.LOGGER = log.get_handler(LOG_CFG, LOG_HANDLER)
        config = yaml.load(open(CFG_FILE, 'r').read())

        if os.path.exists(ROOT_BASEDIR):
            shutil.rmtree(ROOT_BASEDIR)
        if os.path.exists(INTERMEDIARY_BASEDIR):
            shutil.rmtree(INTERMEDIARY_BASEDIR)

        self.root = ssl.OpenSSL(config, ssl.CA_ROOT)
        assert self.root.setup_ca_structure() is True
        open(ROOT_CRT, 'w').write(ROOT_NAME)

        self.inter = ssl.OpenSSL(config, ssl.CA_INTERMEDIARY)
        assert self.inter.setup_ca_structure() is True
        open(INTERMEDIARY_CRT, 'w').write(INTERMEDIARY_NAME)

    def tearDown(self):
        if os.path.exists(ROOT_BASEDIR):
            shutil.rmtree(ROOT_BASEDIR)
        if os.path.exists(INTERMEDIARY_BASEDIR):
            shutil.rmtree(INTERMEDIARY_BASEDIR)

    def test_nonobj_parent(self):
        assert self.inter.updatebundle('somerandomstring') is False

    def test_nonexistent_crt(self):
        tmp_crt = '{0}.temp'.format(INTERMEDIARY_CRT)
        shutil.move(INTERMEDIARY_CRT, tmp_crt)
        assert self.inter.updatebundle(self.root) is False
        shutil.move(tmp_crt, INTERMEDIARY_CRT)

    def test_nonexistent_parent_crt(self):
        tmp_crt = '{0}.temp'.format(ROOT_CRT)
        shutil.move(ROOT_CRT, tmp_crt)
        assert self.inter.updatebundle(self.root) is False
        shutil.move(tmp_crt, ROOT_CRT)

    def test_no_parent_bundle_generates_files(self):
        assert self.inter.updatebundle(self.root) is True

    def test_parent_bundle_generate_files(self):
        open(ROOT_BUNDLE, 'w').write(ROOT_NAME)
        assert self.inter.updatebundle(self.root) is True


class test_OpenSSL_parse_subject:
    def setUp(self):
        log.LOGGER = log.get_handler(LOG_CFG, LOG_HANDLER)
        self.config = yaml.load(open(CFG_FILE, 'r').read())

        if os.path.exists(ROOT_BASEDIR):
            shutil.rmtree(ROOT_BASEDIR)

        self.root = ssl.OpenSSL(self.config, ssl.CA_ROOT)

    def tearDown(self):
        if os.path.exists(ROOT_BASEDIR):
            shutil.rmtree(ROOT_BASEDIR)

    def test_undefined_subject(self):
        assert self.root.parse_subject(None) is False

    def test_empty_subject(self):
        assert self.root.parse_subject('') is False

    def test_numeric_subject(self):
        assert self.root.parse_subject(12345) is False

    def test_invalid_subject(self):
        subj = 'C=NL/ST=Province/L=City/O=Test/OU=Test/CN={0}'.format(
            TLS_NAME
        )
        assert self.root.parse_subject(subj) is False

    def test_generates_dict(self):
        subj = '/C=NL/ST=Province/L=City/O=Test/OU=Test/CN={0}'.format(
            TLS_NAME
        )
        result = self.root.parse_subject(subj)
        assert isinstance(result, dict) is True
        assert len(result) == 6


class test_OpenSSL_parse_db_line:
    def setUp(self):
        log.LOGGER = log.get_handler(LOG_CFG, LOG_HANDLER)
        self.config = yaml.load(open(CFG_FILE, 'r').read())

        if os.path.exists(ROOT_BASEDIR):
            shutil.rmtree(ROOT_BASEDIR)

        self.root = ssl.OpenSSL(self.config, ssl.CA_ROOT)

    def tearDown(self):
        if os.path.exists(ROOT_BASEDIR):
            shutil.rmtree(ROOT_BASEDIR)

    def test_undefined_line(self):
        assert self.root.parse_db_line(None) is False

    def test_empty_line(self):
        assert self.root.parse_db_line('') is False

    def test_line_no_fields(self):
        assert self.root.parse_db_line('blah') is False

    def test_invalid_fields(self):
        line = 'V\t170621191933Z42\tunknown'
        assert self.root.parse_db_line(line) is False

    def test_generates_dictionary(self):
        line = 'V\t170621191933Z\t\t42\tunknown'
        line += '\t/C=NL/ST=Province/L=City/O=Test/OU=Test'
        line += '/CN={0}'.format(TLS_NAME)
        assert isinstance(self.root.parse_db_line(line), dict) is True


class test_OpenSSL_parse_certificate_exceptions:
    def setUp(self):
        log.LOGGER = log.get_handler(LOG_CFG, LOG_HANDLER)
        self.config = yaml.load(open(CFG_FILE, 'r').read())

        if os.path.exists(ROOT_BASEDIR):
            shutil.rmtree(ROOT_BASEDIR)

        self.root = ssl.OpenSSL(self.config, ssl.CA_ROOT)

    def tearDown(self):
        if os.path.exists(ROOT_BASEDIR):
            shutil.rmtree(ROOT_BASEDIR)

    def test_nonexisting_certificate(self):
        assert self.root.parse_certificate(ROOT_CRT) is False


class test_OpenSSL_parse_certificate:
    def setUp(self):
        log.LOGGER = log.get_handler(LOG_CFG, LOG_HANDLER)
        self.config = yaml.load(open(CFG_FILE, 'r').read())
        open(PWFILE, 'w').write(ROOT_NAME)

        if os.path.exists(ROOT_BASEDIR):
            shutil.rmtree(ROOT_BASEDIR)

        self.root = ssl.OpenSSL(self.config, ssl.CA_ROOT)
        cfg = self.root.ca_data['cfg']
        name = self.root.ca_data['name']
        assert self.root.setup_ca_structure() is True
        assert self.root.genkey(cfg, name, pwfile=PWFILE) is True
        assert self.root.selfsign(name, pwfile=PWFILE) is True

    def tearDown(self):
        if os.path.exists(ROOT_BASEDIR):
            shutil.rmtree(ROOT_BASEDIR)

    def test_generates_dictionary(self):
        result = self.root.parse_certificate(ROOT_CRT)
        assert isinstance(result, dict) is True
        assert len(result) == 3


class test_OpenSSL_update_cert_db_exceptions:
    def setUp(self):
        log.LOGGER = log.get_handler(LOG_CFG, LOG_HANDLER)
        self.config = yaml.load(open(CFG_FILE, 'r').read())

        if os.path.exists(ROOT_BASEDIR):
            shutil.rmtree(ROOT_BASEDIR)

        self.root = ssl.OpenSSL(self.config, ssl.CA_ROOT)
        assert self.root.setup_ca_structure() is True

    def tearDown(self):
        if os.path.exists(ROOT_BASEDIR):
            shutil.rmtree(ROOT_BASEDIR)

    def test_nonexisting_db(self):
        tmp_db = '{0}.temp'.format(ROOT_DB)
        shutil.move(ROOT_DB, tmp_db)
        assert self.root.update_cert_db() is False
        shutil.move(tmp_db, ROOT_DB)

    def test_nonexisting_certs_dir(self):
        tmp_certs_dir = '{0}.temp'.format(ROOT_CERTS)
        shutil.move(ROOT_CERTS, tmp_certs_dir)
        assert self.root.update_cert_db() is False
        shutil.move(tmp_certs_dir, ROOT_CERTS)

    def test_skip_list_creation(self):
        line = 'V\t170621191933Z\t\t42\tunknown'
        line += '\t/C=NL/ST=Province/L=City/O=Test/OU=Test'
        line += '/CN={0}\n'.format(TLS_NAME)
        db_data = line
        db_data += line
        open(ROOT_DB, 'w').write(db_data)
        assert self.root.update_cert_db() is True
        os.unlink(ROOT_DB)


class test_OpenSSL_update_cert_db:
    def setUp(self):
        log.LOGGER = log.get_handler(LOG_CFG, LOG_HANDLER)
        self.config = yaml.load(open(CFG_FILE, 'r').read())

        open(PWFILE, 'w').write(ROOT_NAME)

        if os.path.exists(ROOT_BASEDIR):
            shutil.rmtree(ROOT_BASEDIR)
        if os.path.exists(INTERMEDIARY_BASEDIR):
            shutil.rmtree(INTERMEDIARY_BASEDIR)
        if os.path.exists(AUTOSIGN_BASEDIR):
            shutil.rmtree(AUTOSIGN_BASEDIR)

        self.root = ssl.OpenSSL(self.config, ssl.CA_ROOT)
        cfg = self.root.ca_data['cfg']
        name = self.root.ca_data['name']
        assert self.root.setup_ca_structure() is True
        assert self.root.genkey(cfg, name, pwfile=PWFILE) is True
        assert self.root.selfsign(name, pwfile=PWFILE) is True

        self.inter = ssl.OpenSSL(self.config, ssl.CA_INTERMEDIARY)
        cfg = INTERMEDIARY_CFG
        name = INTERMEDIARY_NAME
        csr = INTERMEDIARY_CSR
        crt = INTERMEDIARY_CRT
        assert self.inter.setup_ca_structure() is True
        assert self.inter.genkey(cfg, name, pwfile=PWFILE) is True
        assert self.root.sign_intermediary(csr, crt, PWFILE, 1) is True

        self.autosign = ssl.OpenSSL(self.config, ssl.CA_AUTOSIGN)
        cfg = AUTOSIGN_CFG
        name = AUTOSIGN_NAME
        csr = AUTOSIGN_CSR
        crt = AUTOSIGN_CRT
        assert self.autosign.setup_ca_structure() is True
        assert self.autosign.genkey(cfg, name, pwfile=PWFILE) is True
        assert self.inter.sign_intermediary(csr, crt, PWFILE, 1) is True

        cfg_data = self.autosign.gen_server_cfg(TLS_NAME)
        self.tmp_cfg = '{0}/cfg/{1}.cfg'.format(
            self.root.ca_data['basedir'],
            TLS_NAME
        )
        assert cfg_data is not False
        open(self.tmp_cfg, 'w').write(cfg_data)
        assert self.autosign.genkey(self.tmp_cfg, TLS_NAME) is True
        assert self.autosign.sign(TLS_NAME) is True

    def tearDown(self):
        if os.path.exists(ROOT_BASEDIR):
            shutil.rmtree(ROOT_BASEDIR)
        if os.path.exists(INTERMEDIARY_BASEDIR):
            shutil.rmtree(INTERMEDIARY_BASEDIR)
        if os.path.exists(AUTOSIGN_BASEDIR):
            shutil.rmtree(AUTOSIGN_BASEDIR)
        if os.path.exists(PWFILE):
            os.unlink(PWFILE)
        if os.path.exists(self.tmp_cfg):
            os.unlink(self.tmp_cfg)

    def test_nocerts_updates_database(self):
        open(AUTOSIGN_DB, 'w').write('')
        assert self.autosign.update_cert_db() is True
        assert len(self.autosign.cert_db) == 0

    def test_certs_updates_database(self):
        assert self.autosign.update_cert_db() is True
        assert len(self.autosign.cert_db) == 1

    def test_no_cert_data(self):
        certs = glob.glob('{0}/[0-9A-Z]*.pem'.format(
            self.autosign.ca_data['certsdir']
        ))
        for crt in certs:
            os.unlink(crt)
        assert self.autosign.update_cert_db() is True
        assert len(self.autosign.cert_db) == 1
        assert 'fp' not in self.autosign.cert_db[TLS_NAME]

    def test_cn_not_in_data(self):
        open(AUTOSIGN_DB, 'w').write('')
        assert self.autosign.update_cert_db() is True
        assert len(self.autosign.cert_db) == 0

    def test_invalid_serial(self):
        tmp_db = open(AUTOSIGN_DB, 'r').read()
        tmp_db = tmp_db.replace('\t01', '\t42')
        open(AUTOSIGN_DB, 'w').write(tmp_db)
        assert self.autosign.update_cert_db() is True
        assert len(self.autosign.cert_db) == 1
        assert self.autosign.cert_db[TLS_NAME][0]['serial'] == '42'
