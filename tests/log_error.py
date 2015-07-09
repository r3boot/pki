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


@nose.tools.raises(SystemExit)
def test_message_no_handler():
    log.LOGGER = None
    assert(log.error('Error message')) == None


@nose.tools.raises(SystemExit)
@nose.with_setup(cleanup_logfile)
def test_message_output():
    the_message = 'Error message'
    log.error(the_message)
    output = open(LOG_FILE, 'r').read().strip()
    assert(the_message in output) == True


@nose.tools.raises(SystemExit)
@nose.with_setup(cleanup_logfile, cleanup_logfile)
def test_message_heading():
    the_message = 'Error message'
    log.error(the_message)
    output = open(LOG_FILE, 'r').read().strip()
    assert('ERROR' in output) == True
