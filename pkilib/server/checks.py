"""
... module:: checks
    :platform: Unix, VMS
    :synopsis: Various helper utilities used for performing validation checks

... moduleauthor:: Lex van Roon <r3boot@r3blog.nl>
"""

import re

import pkilib.log as log


def valid_fqdn(fqdn=None):
    """Check if fqdn is valid according to RFC 1123. This means that fqdn can
    only contains (case-insensitive) letters and numbers, together with '.'
    and '-'. All other combinations will return False, just like an empty
    or undefined fqdn.

    :param fqdn:    Fully-Qualified Domain-Name to check
    :type  fqdn:    str
    :returns:       True if fqdn is valid or False if not
    :rtype:         bool
    """
    if fqdn is None:
        log.warning('Fqdn cannot be None')
        return False
    if not isinstance(fqdn, str):
        log.warning('Fqdn needs to be a string')
        return False

    regexp = r'^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*'
    regexp += r'([A-Za-z0-9]  |[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$'
    parser = re.compile(regexp)
    result = parser.search(fqdn)
    return result is not None
