import nose
import os
import sys

sys.path.append('.')


from pkilib import log

CFG_FILE = './config/logging.yml'
LOG_FILE = 'unittest.log'
LOG_HANDLER = 'unittest'


class test_setup:
    def test_nonexisting_config(self):
        assert log.get_handler('somerandomnonexistingfile', 'none') is None

    def test_existing_config(self):
        assert log.get_handler(CFG_FILE, LOG_HANDLER) is not None


class test_methods:
    def setUp(self):
        log.LOGGER = log.get_handler(CFG_FILE, LOG_HANDLER)

    def tearDown(self):
        self.cleanup_logfile()

    def cleanup_logfile(self):
        if os.path.exists(LOG_FILE):
            os.unlink(LOG_FILE)

    def test_debug_no_handler(self):
        log.LOGGER = None
        assert log.debug('Debug message') is None
        log.LOGGER = log.get_handler(CFG_FILE, LOG_HANDLER)

    @nose.with_setup(cleanup_logfile)
    def test_debug_output(self):
        the_message = 'Debug message'
        log.debug(the_message)
        output = open(LOG_FILE, 'r').read().strip()
        assert the_message in output

    @nose.with_setup(cleanup_logfile)
    def test_debug_heading(self):
        the_message = 'Debug message'
        log.debug(the_message)
        output = open(LOG_FILE, 'r').read().strip()
        assert 'DEBUG' in output

    @nose.tools.raises(SystemExit)
    def test_error_no_handler(self):
        log.LOGGER = None
        assert log.error('Error message') is None
        log.LOGGER = log.get_handler(CFG_FILE, LOG_HANDLER)

    @nose.tools.raises(SystemExit)
    @nose.with_setup(cleanup_logfile)
    def test_error_output(self):
        the_message = 'Error message'
        log.error(the_message)
        output = open(LOG_FILE, 'r').read().strip()
        assert the_message in output

    @nose.tools.raises(SystemExit)
    @nose.with_setup(cleanup_logfile)
    def test_error_heading(self):
        the_message = 'Error message'
        log.error(the_message)
        output = open(LOG_FILE, 'r').read().strip()
        assert 'ERROR' in output

    def test_info_no_handler(self):
        log.LOGGER = None
        assert log.info('Informational message') is None
        log.LOGGER = log.get_handler(CFG_FILE, LOG_HANDLER)

    @nose.with_setup(cleanup_logfile)
    def test_info_output(self):
        the_message = 'Informational message'
        log.info(the_message)
        output = open(LOG_FILE, 'r').read().strip()
        assert the_message in output

    @nose.with_setup(cleanup_logfile, cleanup_logfile)
    def test_info_heading(self):
        the_message = 'Informational message'
        log.info(the_message)
        output = open(LOG_FILE, 'r').read().strip()
        assert 'INFO' in output

    def test_warning_no_handler(self):
        log.LOGGER = None
        assert log.warning('Warning message') is None
        log.LOGGER = log.get_handler(CFG_FILE, LOG_HANDLER)

    @nose.with_setup(cleanup_logfile)
    def test_warning_output(self):
        the_message = 'Warning message'
        log.warning(the_message)
        output = open(LOG_FILE, 'r').read().strip()
        assert the_message in output

    @nose.with_setup(cleanup_logfile)
    def test_warning_heading(self):
        the_message = 'Warning message'
        log.warning(the_message)
        output = open(LOG_FILE, 'r').read().strip()
        assert 'WARNING' in output
