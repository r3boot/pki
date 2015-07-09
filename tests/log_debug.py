import nose
import os
import sys

sys.path.insert(0, '../')


from pkilib import log


LOG_FILE = 'pki.log'


def cleanup_logfile():
    if os.path.exists(LOG_FILE):
        os.unlink(LOG_FILE)
    log.LOGGER = log.get_handler('../config/logging.yml', 'unittest')


def test_message_no_handler():
    log.LOGGER = None
    assert(log.debug('Debug message')) == None


@nose.with_setup(cleanup_logfile)
def test_message_output():
    the_message = 'Debug message'
    log.debug(the_message)
    output = open(LOG_FILE, 'r').read().strip()
    assert(the_message in output) == True


@nose.with_setup(cleanup_logfile, cleanup_logfile)
def test_message_heading():
    the_message = 'Debug message'
    log.debug(the_message)
    output = open(LOG_FILE, 'r').read().strip()
    assert('DEBUG' in output) == True
