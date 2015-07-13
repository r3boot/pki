import nose
import os
import shutil
import sys

# TODO: check for Country == 2 chars

try:
    import yaml
except ImportError:
    print('Failed to import PyYaml, please run "pip install pyyaml"')
    sys.exit(1)

sys.path.append('.')


from pkilib import ssl

CFG_FILE = './workspace/unittest/config/pki.yml'
ROOT_TEMPLATE = './workspace/templates/root.template'
ROOT_NAME = 'test-root'
ROOT_BASEDIR = './workspace/{0}'.format(ROOT_NAME)
ROOT_CFG = '{0}/cfg/{1}.cfg'.format(ROOT_BASEDIR, ROOT_NAME)
ROOT_KEY = '{0}/private/{1}.key'.format(ROOT_BASEDIR, ROOT_NAME)
ROOT_CSR = '{0}/csr/{1}.csr'.format(ROOT_BASEDIR, ROOT_NAME)
ROOT_CRT = '{0}/certs/{1}.pem'.format(ROOT_BASEDIR, ROOT_NAME)
ROOT_EXT = 'root_ca_ext'

AUTOSIGN_NAME = 'test-autosign'
AUTOSIGN_BASEDIR = './workspace/{0}'.format(AUTOSIGN_NAME)
AUTOSIGN_CFG = '{0}/cfg/{1}.cfg'.format(AUTOSIGN_BASEDIR, AUTOSIGN_NAME)
AUTOSIGN_KEY = '{0}/private/{1}.key'.format(AUTOSIGN_BASEDIR, AUTOSIGN_NAME)
AUTOSIGN_CSR = '{0}/csr/{1}.csr'.format(AUTOSIGN_BASEDIR, AUTOSIGN_NAME)
AUTOSIGN_EXT = 'server_ext'
PWFILE = './workspace/pwfile.input'


class test_generic:
    @nose.tools.raises(SystemExit)
    def test_invalid_ca_type(self):
        assert(ssl.OpenSSL({}, 'somerandomcatype')) == None


class test_root_ca:
    def setUp(self):
        config = yaml.load(open(CFG_FILE, 'r').read())
        self.ca = ssl.OpenSSL(config, ssl.CA_ROOT)

    def tearDown(self):
        self.clean_workspace()

    def clean_workspace(self):
        basedir = self.ca.ca_data['basedir']
        if os.path.exists(basedir):
            shutil.rmtree(basedir)

    def init_workspace(self):
        self.clean_workspace()
        self.ca.setup_ca_structure()
        self.generate_pwfile()

    def generate_pwfile(self):
        open(PWFILE, 'w').write('{0}\n'.format(ROOT_NAME))

    def test_filled_ca_data(self):
        assert(len(self.ca.ca_data) > 0) == True

    def test_setup_ca_structure_existing_basedir(self):
        os.mkdir(self.ca.ca_data['basedir'])
        assert(self.ca.setup_ca_structure()) == False
        os.rmdir(self.ca.ca_data['basedir'])

    def test_setup_ca_structure_nonexisting_root_template(self):
        tmp_cfg = '{0}.temp'.format(ROOT_TEMPLATE)
        shutil.move(ROOT_TEMPLATE, tmp_cfg)
        assert(self.ca.setup_ca_structure()) == False
        shutil.move(tmp_cfg, ROOT_TEMPLATE)

    def test_setup_ca_structure_structure_created(self):
        self.init_workspace()
        basedir = self.ca.ca_data['basedir']
        cfg = '{0}/cfg/{1}.cfg'.format(basedir, self.ca.ca_data['name'])
        ca_dirs = ['certs', 'cfg', 'crl', 'csr', 'db', 'private']
        open('/tmp/out', 'w').write(self.ca.ca_data['basedir'])
        assert(os.path.exists(self.ca.ca_data['basedir']))
        for DIR in ca_dirs:
            dest_dir = '{0}/{1}'.format(basedir, DIR)
            assert(os.path.exists(dest_dir)) == True
        assert(os.path.exists(cfg)) == True

    def test_setup_ca_structure_incomplete_template(self):
        old_cn = self.ca.ca_data['cn']
        del(self.ca.ca_data['cn'])
        self.init_workspace()
        assert(self.ca.setup_ca_structure()) == False
        self.ca.ca_data['cn'] = old_cn

    def test_genkey_no_configuration(self):
        self.init_workspace()
        os.unlink(ROOT_CFG)
        assert(self.ca.genkey(ROOT_CFG, ROOT_NAME, pwfile=PWFILE)) == False

    def test_genkey_existing_key(self):
        self.init_workspace()
        open(ROOT_KEY, 'w').write(ROOT_NAME)
        assert(self.ca.genkey(ROOT_CFG, ROOT_NAME, pwfile=PWFILE)) == False

    def test_genkey_existing_csr(self):
        self.init_workspace()
        open(ROOT_CSR, 'w').write(ROOT_NAME)
        assert(self.ca.genkey(ROOT_CFG, ROOT_NAME, pwfile=PWFILE)) == False

    def test_genkey_undefined_pwfile(self):
        self.init_workspace()
        assert(self.ca.genkey(ROOT_CFG, ROOT_NAME, pwfile=None)) == False

    def test_genkey_nonexisting_pwfile(self):
        self.init_workspace()
        os.unlink(PWFILE)
        assert(self.ca.genkey(ROOT_CFG, ROOT_NAME, pwfile=PWFILE)) == False

    def test_genkey_generates_files(self):
        self.init_workspace()
        self.ca.genkey(ROOT_CFG, ROOT_NAME, pwfile=PWFILE)
        assert(os.path.exists(ROOT_KEY)) == True
        assert(os.path.exists(ROOT_CSR)) == True

    def test_selfsign_no_configuration(self):
        self.init_workspace()
        os.unlink(ROOT_CFG)
        assert(self.ca.selfsign(ROOT_NAME, ROOT_EXT, pwfile=PWFILE)) == False

    def test_selfsign_undefined_pwfile(self):
        self.init_workspace()
        assert(self.ca.selfsign(ROOT_NAME, ROOT_EXT, pwfile=None)) == False

    def test_selfsign_nonexisting_pwfile(self):
        self.init_workspace()
        os.unlink(PWFILE)
        assert(self.ca.selfsign(ROOT_NAME, ROOT_EXT, pwfile=PWFILE)) == False

    def test_selfsign_no_csr(self):
        self.init_workspace()
        self.ca.genkey(ROOT_CFG, ROOT_NAME, pwfile=PWFILE)
        os.unlink(ROOT_CSR)
        assert(self.ca.selfsign(ROOT_NAME, ROOT_EXT, pwfile=PWFILE)) == False

    def test_selfsign_existing_crt(self):
        self.init_workspace()
        self.ca.genkey(ROOT_CFG, ROOT_NAME, pwfile=PWFILE)
        open(ROOT_CRT, 'w').write(ROOT_NAME)
        assert(self.ca.selfsign(ROOT_NAME, ROOT_EXT, pwfile=PWFILE)) == False

    def test_selfsign_generates_files(self):
        self.init_workspace()
        self.ca.genkey(ROOT_CFG, ROOT_NAME, pwfile=PWFILE)
        self.ca.selfsign(ROOT_NAME, ROOT_EXT, pwfile=PWFILE)
        assert(os.path.exists(ROOT_CRT)) == True


class test_autosign_ca:
    def setUp(self):
        config = yaml.load(open(CFG_FILE, 'r').read())
        self.ca = ssl.OpenSSL(config, ssl.CA_AUTOSIGN)

    def tearDown(self):
        self.clean_workspace()

    def clean_workspace(self):
        basedir = self.ca.ca_data['basedir']
        if os.path.exists(basedir):
            shutil.rmtree(basedir)

    def init_workspace(self):
        self.clean_workspace()
        self.ca.setup_ca_structure()
        self.generate_pwfile()

    def generate_pwfile(self):
        open(PWFILE, 'w').write('{0}\n'.format(AUTOSIGN_NAME))

    def test_genkey_generates_files(self):
        self.init_workspace()
        self.ca.genkey(AUTOSIGN_CFG, AUTOSIGN_NAME)
        assert(os.path.exists(AUTOSIGN_KEY)) == True
        assert(os.path.exists(AUTOSIGN_CSR)) == True

    def test_selfsign_generates_files(self):
        self.init_workspace()
        self.ca.genkey(AUTOSIGN_CFG, AUTOSIGN_NAME)
        self.ca.selfsign(AUTOSIGN_NAME, AUTOSIGN_EXT)
