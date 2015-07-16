import nose
import os
import shlex
import sys

sys.path.append('.')


from pkilib import utils


class test_fhost_unix:
    def test_converts_hostname(self):
        assert utils.fhost('some.host.name') == 'some.host.name'


class test_fhost_vms:
    def setUp(self):
        utils.C_OSNAME = 'OpenVMS'

    def tearDown(self):
        utils.C_OSNAME = os.uname()[0]

    def test_fhost_integer(self):
        assert utils.fhost(1234567890) == ''

    def test_converts_hostname(self):
        assert utils.fhost('some.host.name') == 'some_host_name'


class test_fpath_unix:
    def test_fpath_unix(self):
        assert utils.fpath('/some/path/ghe.txt') == '/some/path/ghe.txt'


class test_fpath_vms:
    def setUp(self):
        utils.C_OSNAME = 'OpenVMS'

    def tearDown(self):
        utils.C_OSNAME = os.uname()[0]

    def test_file_path(self):
        assert utils.fpath('file.txt') == 'file.txt'

    def test_empty_path(self):
        assert utils.fpath('') == ''

    def test_undefined_path(self):
        assert utils.fpath(None) == ''

    def test_integer(self):
        assert utils.fpath(1234567890) == ''

    def test_1component(self):
        assert utils.fpath('/some') == 'some:'

    def test_2component_file(self):
        assert utils.fpath('/some/file.txt') == 'some:file.txt'

    def test_2component_dir(self):
        assert utils.fpath('/some/dir', isdir=True) == 'some:[dir]'

    def test_3component_file(self):
        assert utils.fpath('/some/path/file.txt') == 'some:[path]file.txt'

    def test_3component_dir(self):
        assert utils.fpath('/some/dir/path', isdir=True) == 'some:[dir.path]'

    def test_long(self):
        assert utils.fpath('/some/path/thats/longer/file.txt') \
            == 'some:[path.thats.longer]file.txt'


class test_gen_enddate:
    def test_return_type(self):
        assert isinstance(utils.gen_enddate(10), str) is True

    def test_length(self):
        assert len(utils.gen_enddate(10)) == 15

    def test_invalid_input(self):
        assert utils.gen_enddate('somerandomstring') is None

    def test_undefined_input(self):
        assert utils.gen_enddate(None) is None


class test_run_unix:
    def test_uname(self):
        assert utils.run('uname -s').strip() == os.uname()[0]

    def test_nonexisting(self):
        assert utils.run('somerandomunknownfilename') is None

    def test_stdout(self):
        assert utils.run('uname -s', stdout=True) is None

    def test_empty_command(self):
        assert utils.run('') is None

    def test_undefined_command(self):
        assert utils.run(None) is None

    def test_integer_command(self):
        assert utils.run(1234567890) is None

    def test_list_command(self):
        assert utils.run(shlex.split('uname -s')).strip() == os.uname()[0]


class test_run_vms:
    def setUp(self):
        utils.C_OSNAME = 'OpenVMS'

    def tearDown(self):
        utils.C_OSNAME = os.uname()[0]

    def test_uname(self):
        assert utils.run('uname -s').strip() == os.uname()[0]

    def test_list_command(self):
        assert utils.run(shlex.split('uname -s')).strip() == os.uname()[0]


class test_gentoken:
    def test_generates_token(self):
        assert len(utils.gentoken()) == 64


class test_mkstemp:
    def test_opens_fd_locally(self):
        fd = utils.mkstemp()
        assert fd.closed is False
        assert os.path.exists(fd.name)
        fd.close()
        os.unlink(fd.name)

    def test_opens_fd_var_tmp(self):
        fd = utils.mkstemp(prefix='/var/tmp/')
        assert fd.closed is False
        assert os.path.exists(fd.name)
        fd.close()
        os.unlink(fd.name)

    def test_not_allowed_prefix(self):
        assert utils.mkstemp('/') is False

    def test_nonexisting_prefix(self):
        assert utils.mkstemp(prefix='/nonexisting/') is False
