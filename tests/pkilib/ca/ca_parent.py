import nose
import os
import shutil
import sys

try:
    import yaml
except ImportError:
    print('Failed to import PyYaml, please run "pip install yaml"')
    sys.exit(1)


sys.path.insert(0, '../')


from pkilib import ca

NAME_PREFIX = 'test-'
WORKSPACE = './workspace'


def get_config():
    return yaml.load(open('./config/pki.yml', 'r').read())


def get_ca():
    wrkdir = '{0}/test-{1}'.format(WORKSPACE, ca.CA_PARENT)
    if os.path.exists(wrkdir):
        shutil.rmtree(wrkdir)

    config = get_config()
    ca_obj = ca.ParentCA(config)
    return ca_obj


def test_class_creation():
    config = get_config()
    assert(ca.ParentCA(config)) != None


def test_class_ca_type():
    testca = get_ca()
    assert(testca.ca_type) == ca.CA_PARENT


def test_class_ca_name():
    testca = get_ca()
    assert(testca.name) == '{0}{1}'.format(NAME_PREFIX, ca.CA_PARENT)


def test_class_basedir():
    testca = get_ca()
    assert(os.path.exists(testca.basedir)) == True


def test_root_template():
    testca = get_ca()
    template_file = '{0}/templates/root.template'.format(testca.workspace)
    assert(os.path.exists(template_file)) == True


def test_setup_directories():
    testca = get_ca()
    testca.setup()
    assert(os.path.exists(testca.basedir)) == True


def test_setup_db_exists():
    testca = get_ca()
    testca.setup()
    db = testca.ca_data['db']
    assert(os.path.exists(db)) == True


def test_setup_db_attr_exists():
    testca = get_ca()
    testca.setup()
    db_attr = testca.ca_data['db_attr']
    assert(os.path.exists(db_attr)) == True


def test_setup_crt_idx_exists():
    testca = get_ca()
    testca.setup()
    crt_idx = testca.ca_data['crt_idx']
    assert(os.path.exists(crt_idx)) == True


def test_setup_crt_idx_content():
    testca = get_ca()
    testca.setup()
    crt_idx = testca.ca_data['crt_idx']
    content = open(crt_idx, 'r').read().strip()
    assert(content == '01') == True


def test_setup_crl_idx_exists():
    testca = get_ca()
    testca.setup()
    crt_idx = testca.ca_data['crl_idx']
    assert(os.path.exists(crt_idx)) == True


def test_setup_crl_idx_content():
    testca = get_ca()
    testca.setup()
    crt_idx = testca.ca_data['crl_idx']
    content = open(crt_idx, 'r').read().strip()
    assert(content == '01') == True


def test_setup_cfg_exists():
    testca = get_ca()
    testca.setup()
    assert(os.path.exists(testca.ca_data['cfg'])) == True


def test_setup_cfg_templated():
    testca = get_ca()
    testca.setup()
    name = testca.name
    content = open(testca.ca_data['cfg'], 'r').read().strip()
    assert(name in content) == True
