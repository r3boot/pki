"""
.. module:: log
   :platform: Unix, VMS
   :synopsis: Module containing various wrappers around python logging

.. moduleauthor:: Lex van Roon <r3boot@r3blog.nl>
"""
import logging
import logging.config
import os
import sys

try:
    import yaml
except ImportError:
    print('Failed to import PyYaml, please run "pip install pyyaml"')
    sys.exit(1)


# Global variable containing the system logger
LOGGER = None


def get_handler(cfg_file, log_handler):
    """Helper function which loads the log configuration from disk, and returns
    a reference to the python logger object for this script. Make sure that
    you configure this logging configuration correctly, since this function is
    dependent on it.

    >>> get_handler('./logging.yml', 'initpki')
    <logging.Logger object at 0x7fa86cd4f748>

    You need to use this function during script initialization to setup the
    global LOGGER variable within this module, so all wrappers can do their
    magic. To do this, place code along the lines below in the beginning of
    your script

    >>> import pkilib.log
    >>> log.LOGGER = log.get_handler('./logging.yml', 'initpki')

    :param cfg_file:    Path to the yaml-based configuration file
    :type  cfg_file:    str
    :param log_handler: Name of the log handler to use
    :type  log_handler: str
    :returns:           Reference to a python logging handler or None
    :rtype:             logging.Logger, None
    """
    if not os.path.exists(cfg_file):
        print('{0}: No such file or directory'.format(cfg_file))
        return None
    log_cfg = yaml.load(open(cfg_file, 'r').read())
    logging.config.dictConfig(log_cfg)
    return logging.getLogger(log_handler)


def info(message):
    """Short-hand wrapper around logger.info. If logging has not been setup,
    it will display a nag message telling you that.

    >>> info('This is an informational message')
    [    INFO]: This is an informational message

    :param message:     The message to display
    :type  message:     str
    :returns:           Flag indicating if logging was enabled
    :rtype:             bool
    """
    # Handle case where logger has not been setup
    if not LOGGER:
        print('[logging not configured] {0}'.format(message))
        return
    LOGGER.info(message)
    return True


def warning(message):
    """Short-hand wrapper around logger.warning. If logging has not been setup,
    it will display a nag message telling you that.

    >>> warning('This is a warning message')
    [ WARNING]: This is a warning message

    :param message:     The message to display
    :type  message:     str
    :returns:           Flag indicating if logging was enabled
    :rtype:             bool
    """
    # Handle case where logger has not been setup
    if not LOGGER:
        print('[logging not configured] {0}'.format(message))
        return
    LOGGER.warning(message)
    return True


def debug(message):
    """Short-hand wrapper around logger.debug. If logging has not been setup,
    it will display a nag message telling you that.

    >>> debug('This is a debugging message')
    [   DEBUG]: This is a debugging message

    :param message:     The message to display
    :type  message:     str
    :returns:           Flag indicating if logging was enabled
    :rtype:             bool
    """
    # Handle case where logger has not been setup
    if not LOGGER:
        print('[logging not configured] {0}'.format(message))
        return
    LOGGER.debug(message)
    return True


def error(message):
    """Short-hand wrapper around logger.error. If logging has not been setup,
    it will display a nag message telling you that. This function will also
    run sys.exit(1) to abort the program.

    >>> error('This is an error message')
    [   ERROR]: This is an error message

    :param message:     The message to display
    :type  message:     str
    :raises:            SystemExit
    """
    # Handle case where logger has not been setup
    if not LOGGER:
        print('[logging not configured] {0}'.format(message))
    else:
        LOGGER.error(message)
    raise SystemExit
