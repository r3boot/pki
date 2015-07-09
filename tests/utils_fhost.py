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
    assert utils.fhost('some.host.name') == 'some.host.name'


@nose.with_setup(vms_spoof, undo_vms_spoof)
def test_vms():
    assert utils.fhost('some.host.name') == 'some_host_name'


@nose.with_setup(vms_spoof, undo_vms_spoof)
def test_integer():
    assert utils.fhost(1234567890) == ''
