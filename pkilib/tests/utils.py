import nose
import os
import shlex
import sys

sys.path.append('.')


from pkilib import utils


class test_unix:
    def test_fhost_good(self):
        assert utils.fhost('some.host.name') == 'some.host.name'

    def test_fhost_integer(self):
        assert utils.fhost(1234567890) == ''

    def test_fpath_unix(self):
        assert utils.fpath('/some/path/ghe.txt') == '/some/path/ghe.txt'

    def test_gen_enddate_type(self):
        assert(isinstance(utils.gen_enddate(10), str)) == True

    def test_gen_enddate_length(self):
        assert(len(utils.gen_enddate(10)) == 15) == True

    def test_gen_enddate_string(self):
        assert(utils.gen_enddate('somerandomstring')) == None

    def test_gen_enddate_empty(self):
        assert(utils.gen_enddate(None)) == None

    def test_run_uname(self):
        assert utils.run('uname -s').strip() == os.uname()[0]

    @nose.tools.raises(FileNotFoundError)
    def test_run_nonexisting(self):
        assert utils.run('somerandomunknownfilename') == None

    def test_run_uname_stdout(self):
        assert utils.run('uname -s', stdout=True) == None

    def test_run_empty_command(self):
        assert utils.run('') == None

    def test_run_none_command(self):
        assert utils.run(None) == None

    def test_run_integer_command(self):
        assert utils.run(1234567890) == None

    def test_run_list_command(self):
        assert utils.run(shlex.split('uname -s')).strip() == os.uname()[0]


class test_vms:
    def setUp(self):
        utils.C_OSNAME = 'OpenVMS'

    def tearDown(self):
        utils.C_OSNAME = os.uname()[0]

    def test_fhost_vms(self):
        assert utils.fhost('some.host.name') == 'some_host_name'

    def test_fhost_integer(self):
        assert utils.fhost(1234567890) == ''

    def test_fpath_file(self):
        assert utils.fpath('file.txt') == 'file.txt'

    def test_fpath_empty(self):
        assert utils.fpath('') == ''

    def test_fpath_none(self):
        assert utils.fpath(None) == ''

    def test_fpath_1component(self):
        assert utils.fpath('/some') == 'some:'

    def test_fpath_2component_dir(self):
        assert utils.fpath('/some/path') == 'some:[path]'

    def test_fpath_2component_file(self):
        assert utils.fpath('/some/file.txt') == 'some:file.txt'

    def test_fpath_3component_file(self):
        assert utils.fpath('/some/path/file.txt') == 'some:[path]file.txt'

    def test_fpath_long(self):
        assert utils.fpath('/some/path/thats/longer/file.txt') \
            == 'some:[path.thats.longer]file.txt'

    def test_fpath_integer(self):
        assert utils.fpath(1234567890) == ''

    def test_run_uname(self):
        assert utils.run('uname -s').strip() == os.uname()[0]

    def test_run_list_command(self):
        assert utils.run(shlex.split('uname -s')).strip() == os.uname()[0]

if __name__ == '__main__':
    nose.main()
