import nose
import os
import shlex
import sys

sys.path.insert(0, '../')


from pkilib import utils


def vms_spoof():
    utils.C_OSNAME = 'OpenVMS'


def undo_vms_spoof():
    utils.C_OSNAME = os.uname()[0]


def test_unix_uname():
    assert utils.run('uname -s').strip() == os.uname()[0]


@nose.with_setup(vms_spoof, undo_vms_spoof)
def test_vms_uname():
    assert utils.run('uname -s').strip() == os.uname()[0]


def test_nonexisting():
    assert utils.run('somerandomunknownfilename') == None


def test_unix_uname_stdout():
    assert utils.run('uname -s', stdout=True) == None


def test_unix_empty_command():
    assert utils.run('') == None


def test_unix_none_command():
    assert utils.run(None) == None


def test_unix_integer_command():
    assert utils.run(1234567890) == None


def test_unix_list_command():
    assert utils.run(shlex.split('uname -s')).strip() == os.uname()[0]


@nose.with_setup(vms_spoof, undo_vms_spoof)
def test_vms_list_command():
    assert utils.run(shlex.split('uname -s')).strip() == os.uname()[0]
