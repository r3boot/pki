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
    assert(log.info('Informational message')) == None


@nose.with_setup(cleanup_logfile)
def test_message_output():
    the_message = 'Informational message'
    log.info(the_message)
    output = open(LOG_FILE, 'r').read().strip()
    assert(the_message in output) == True


@nose.with_setup(cleanup_logfile, cleanup_logfile)
def test_message_heading():
    the_message = 'Informational message'
    log.info(the_message)
    output = open(LOG_FILE, 'r').read().strip()
    assert('INFO' in output) == True
