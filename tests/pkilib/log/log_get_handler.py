import nose
import os
import sys

sys.path.insert(0, '../')


from pkilib import log


def test_nonexisting_config():
    assert(log.get_handler('somerandomnonexistingfile', 'none')) == None


def test_existing_config():
    assert(log.get_handler('../config/logging.yml', 'none')) != None
