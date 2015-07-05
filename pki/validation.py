
import bottle
import glob
import json
import os
import re
import shlex
import socket
import subprocess

from pki.constants  import *
from pki.logging    import *
from pki.utils      import *

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

    ## Check if srcip is one of fqdn's ip addresses
    try:
        socket_data = socket.getaddrinfo(fqdn, 80)
    except socket.gaierror, e:
        warning('Failed to resolve ptr records for {0}'.format(fqdn, e))
        return False
    except:
        warning('Unknown error resolving PTR records for {0}'.format(fqdn))
        return False

    ips = []
    for item in socket_data:
        ip = item[4][0]
        if ip not in ips:
            ips.append(ip)
    if srcip not in ips:
        ## Permissive
        warning('{0} is not a valid ip address for {1}'.format(srcip, fqdn))
        return True

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
    info(cmdline)
    cmdline = shlex.split(cmdline)
    proc = subprocess.Popen(cmdline, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, err = proc.communicate()
    info(err)
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


def valid_crt(ca, crt):
    """ valid_crt:      Check if crt is a valid certificate in our pki

    @param:     ca      Dictionary containing information about the CA
    @param:     crt     Path towards a file containing the certificate
    @param:     fqdn    Fully-Qualified domain-name for the host
    @return:    True    The certificate belongs to both this PKI and the host
    @return:    False   The certificate does not belong to either this PKI or
                        the host
    """
    raw_data = bottle.request.body.read()
    data = json.loads(raw_data)

    if 'fqdn' not in data:
        warning('No fqdn found in request')
        return False
    fqdn = data['fqdn']

    if 'crt' not in data:
        warning('No certificate data found in request')
        return False
    crt_data = data['crt']

    ## Save the certificate to be revoked for later usage
    try:
        fd = mkstemp(prefix=C_TMPDIR)
    except OSError, e:
        warning('Error creating temporary file: {0}'.format(e))
        return bottle.HTTPResponse(status=403)
    fd.write(crt_data)
    fd.close()

    ## Get the fingerprint of the certificate
    cmdline = 'openssl x509 -in {0} -noout -fingerprint'.format(fd.name)
    cmdline = shlex.split(cmdline)
    proc = subprocess.Popen(cmdline, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, err = proc.communicate()
    fingerprint = output.replace('SHA1 Fingerprint=', '').strip()

    ### Close the file descriptor towards the temporary certificate
    os.unlink(fd.name)

    ## Get a list of valid fingerprints from the locally generated certs
    local_fingerprints = []
    crt_dir = '{0}/certs'.format(ca.ca['basedir'])
    for local_cert in glob.glob('{0}/[0-9A-Z]*.pem'.format(crt_dir)):
        cmdline = 'openssl x509 -in {0} -noout -fingerprint'.format(local_cert)
        cmdline = shlex.split(cmdline)
        proc = subprocess.Popen(cmdline, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, err = proc.communicate()
        local_fp = output.replace('SHA1 Fingerprint=', '').strip()
        local_fingerprints.append(local_fp)

    ## Check if crt is a valid certificate
    if fingerprint in local_fingerprints:
        return True
    else:
        warning('Certificate for {0} has an unknown fingerprint'.format(fqdn))
        return False
