
import bottle
import json
import os
import re
import shlex
import socket
import subprocess

from pki.logging    import *

_subject_to_yaml = {
    'C':    'country',
    'ST':   'province',
    'L':    'city',
    'O':    'organization',
    'OU':   'unit',
}

def valid_fqdn(fqdn):
    """ valid_fqdn: Matches valid hostnames based on RFC1123

    @param:     fqdn    Fully-qualified domain-name to check
    @return:    True    fqdn is a valid hostname
    @return:    False   fqdn does not match a valid hostname
    """
    r = re.compile('^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$')
    result = r.search(fqdn)
    return result != None


def valid_srcip(srcip, fqdn):
    """ valid_srcip:    Check if the source ip matches the fqdn

    @param:     srcip   Source ip address in string form
    @param:     fqdn    Fully-qualified domain-name to match against srcip
    @return:    True    srcip is one of fqdn's ip addresses
    @return:    False   srcip does not match any of fqdn's ip addresses
    """

    ## First, check if srcip is one of fqdn's ip addresses
    try:
        socket_data = socket.getaddrinfo(fqdn, 80)
    except socket.gaierror:
        warning('Failed to resolve ptr records for {0}'.format(fqdn))
        return False
    ips = []
    for item in socket_data:
        ip = item[4][0]
        if ip not in ips:
            ips.append(ip)
    if srcip in ips:
        return True
    else:
        warning('{0} does not belong to {1}'.format(srcip, fqdn))
        return True


def valid_token(store, fqdn, token):
    """ valid_token:    Check if the token exists and belongs to fqdn

    @param:     store   Path to a file containing the store of tokens in json
    @param:     fqdn    Fully-qualified domain-name to match with
    @param:     token   Client token
    @return:    True    fqdn + token are specified as a couple in the store
    @return:    False   Either fqdn does not exists, or the token is invalid
    """
    if not os.path.exists(store):
        warning('{0} does not exist, cannot validate token'.format(store))
        return False

    ## Check if fqdn has a token at all
    tokens = json.loads(open(store, 'r').read())
    if fqdn not in tokens:
        warning('{0} does not have a token'.format(fqdn))
        return False

    ## Check if the token matches the stored token for fqdn
    if tokens[fqdn] == token:
        return True
    else:
        warning('Token mismatch for {0}'.format(fqdn))
        return False


def valid_csr(ca, csr, fqdn):
    """ valid_csr:      Validate various fields within the csr

    @param:     ca          Dictionary containing information of the signing CA
    @param:     csr         Path to the file containing the csr'
    @param:     fqdn        Fully-qualified domain-name to check against
    @return:    True        All checked fields validate
    @return:    False       One or more fields have issues
    """
    cmdline = 'openssl req -in {0} -noout -subject'.format(csr)
    cmdline = shlex.split(cmdline)
    proc = subprocess.Popen(cmdline, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, err = proc.communicate()
    output = output.replace('subject=/', '').strip()
    raw_subject = output.split('/')
    subject = {}
    for item in raw_subject:
        field, value = item.split('=')

        ## CN field needs special handling
        if field == 'CN':
            if value != fqdn:
                warning('CN field does not match requested fqdn')
                return False
            else:
                continue

        ## Check if the field exists
        if _subject_to_yaml[field] not in ca.cfg['common']:
            warning('Unknown field found in csr: {0}'.format(field))
            return False

        ## Check if field matches the values for the CA
        if ca.cfg['common'][_subject_to_yaml[field]] != value:
            warning('{0} field does not match the default fields'.format(field))
            return False

    return True
