import nose
import os
import sys

sys.path.insert(0, '../')


from pkilib import utils


def vms_spoof():
    utils.C_OSNAME = 'OpenVMS'


def undo_vms_spoof():
    utils.C_OSNAME = os.uname()[0]


def test_unix():
    assert utils.fpath('/some/path/ghe.txt') == '/some/path/ghe.txt'


@nose.with_setup(vms_spoof, undo_vms_spoof)
def test_vms_file():
    assert utils.fpath('file.txt') == 'file.txt'


@nose.with_setup(vms_spoof, undo_vms_spoof)
def test_vms_empty():
    assert utils.fpath('') == ''


@nose.with_setup(vms_spoof, undo_vms_spoof)
def test_vms_none():
    assert utils.fpath(None) == ''


@nose.with_setup(vms_spoof, undo_vms_spoof)
def test_vms_1component():
    assert utils.fpath('/some') == 'some:'


@nose.with_setup(vms_spoof, undo_vms_spoof)
def test_vms_2component_dir():
    assert utils.fpath('/some/path') == 'some:[path]'


@nose.with_setup(vms_spoof, undo_vms_spoof)
def test_vms_2component_file():
    assert utils.fpath('/some/file.txt') == 'some:file.txt'


@nose.with_setup(vms_spoof, undo_vms_spoof)
def test_vms_3component_file():
    assert utils.fpath('/some/path/file.txt') == 'some:[path]file.txt'


@nose.with_setup(vms_spoof, undo_vms_spoof)
def test_vms_long():
    assert utils.fpath('/some/path/thats/longer/file.txt') \
        == 'some:[path.thats.longer]file.txt'


@nose.with_setup(vms_spoof, undo_vms_spoof)
def test_vms_integer():
    assert utils.fpath(1234567890) == ''
