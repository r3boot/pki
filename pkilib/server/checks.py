"""
... module:: checks
    :platform: Unix, VMS
    :synopsis: Various helper utilities used for performing validation checks

... moduleauthor:: Lex van Roon <r3boot@r3blog.nl>
"""

import re
import socket

import pkilib.log as log


# Global flag indicting permissive mode
PERMISSIVE_MODE = False


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


def owns_fqdn(srcip=None, fqdn=None):
    """Check if a fqdn is owned by srcip. It does this by performing a DNS
    lookup for the PTR records of fqdn, and matches srcip against these. If
    a match is found, True is returned, else False. Note that the ip check
    can be overridden by using PERMISSIVE_MODE. This function will also
    return False if srcip and/or fqdn are invalid.

    :param srcip:   Source ip address to check against
    :type  srcip:   str
    :param fqdn:    Fully-Qualified Domain-Name to check
    :type  fqdn:    str
    :returns:       True if fqdn is owned by srcip, else False
    :rtype:         bool
    """
    if not srcip:
        log.warning('srcip cannot be None')
        return False
    if not isinstance(srcip, str):
        log.warning('srcip need to be a string')
        return False
    if not valid_fqdn(fqdn):
        return False

    # Get the PTR entries for fqdn
    try:
        socket_data = socket.getaddrinfo(fqdn, 80)
    except socket.gaierror as err:
        log.warning('Failed to resolve PTR for {0}: {1}'.format(fqdn, err))
        return False

    # Parse socket_data and assemble a list of ip addresses for fqdn
    ips = []
    for item in socket_data:
        ipaddr = item[4][0]
        if ipaddr not in ips:
            ips.append(ipaddr)

    # Check if srcip is one of the ip addresses of fqdn. Return True if
    # permissive mode is enabled
    if srcip not in ips:
        if not PERMISSIVE_MODE:
            log.warning('{0} does not belong to {1}'.format(fqdn, srcip))
            return False
        else:
            log.warning('{0} does not belong to {1} (permissive)'.format(
                fqdn, srcip
            ))
    return True
