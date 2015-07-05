
from Crypto.Hash    import SHA256

import bottle
import mako.template
import json
import os
import random
import shlex
import socket
import subprocess

from pki.constants          import *
from pki.logging            import *
from pki.utils              import *
from pki.validation         import *
from pki.validator.client   import ValidatorClient

ca =  None


def validate_request(f):
    def perform_validation(**kwargs):
        raw_data = bottle.request.body.read()
        data = json.loads(raw_data)

        if 'fqdn' not in data:
            warning('fqdn not found in request')
            return bottle.HTTPResponse(status=403)

        if 'token' not in data:
            warning('token not found in request')
            return bottle.HTTPResponse(status=403)

        fqdn = data['fqdn']
        token = data['token']
        srcip = bottle.request.remote_addr

        ## Perform fqdn validation
        if not valid_fqdn(fqdn):
            return bottle.HTTPResponse(status=403)
        debug('{0} is a valid RFC1123 hostname'.format(fqdn))

        ## Perform source ip address validation
        if not valid_srcip(srcip, fqdn):
            return bottle.HTTPResponse(status=403)
        debug('{0} is a valid source ip for {1}'.format(srcip, fqdn))

        ## Check if a token is present and validate it
        token_store = '{0}/tokens.json'.format(ca.cfg['common']['workspace'])
        if not valid_token(token_store, fqdn, token):
            return bottle.HTTPResponse(status=403)
        debug('{0} uses a valid token'.format(fqdn))

        ## Check if a csr is present in the request, and validate it
        if 'csr' in data:
            csr_data = data['csr']
            try:
                fd = mkstemp(prefix=C_TMPDIR)
            except OSError, e:
                warning('Error creating temporary file: {0}'.format(e))
                return bottle.HTTPResponse(status=403)
            fd.write(csr_data)
            fd.close()
            result = valid_csr(ca, cfname(fd.name), fqdn=fqdn)
            os.unlink(fd.name)
            if not result:
                return bottle.HTTPResponse(status=403)
            debug('{0} submitted a valid csr'.format(fqdn))

        ## Check if a crt is present in the request, and validate it
        if 'crt' in data:
            crt_data = data['crt']
            try:
                fd = mkstemp(prefix=C_TMPDIR)
            except OSError, e:
                warning('Error creating temporary file: {0}'.format(e))
                return bottle.HTTPResponse(status=403)
            fd.write(crt_data)
            fd.close()
            result = valid_crt(ca, cfname(fd.name))
            os.unlink(fd.name)
            if not result:
                return bottle.HTTPResponse(status=403)
            debug('{0} submitted a valid crt'.format(fqdn))

        ## Run and return the decorated function
        return f(**kwargs)
    return perform_validation


@bottle.get('/')
def index():
    return 'PKI api service\n'


@bottle.post('/token/<fqdn>')
def generate_token(fqdn):
    raw_data = bottle.request.body.read()
    data = json.loads(raw_data)

    template_file = '{0}/templates/client_yml.template'.format(ca.cfg['common']['workspace'])
    if not os.path.exists(template_file):
        warning('{0} does not exist'.format(template_file))
        return bottle.HTTPResponse(status=501, body='Internal error')

    debug('Received new token request from {0}'.format(fqdn))
    req_token = data['token']
    if not ValidatorClient(fqdn).validate(req_token=req_token):
        warning('{0} initial token mismatch'.format(fqdn))
        return bottle.HTTPResponse(status=403, body='Not authenticated')

    token = gentoken()

    token_store = '{0}/tokens.json'.format(ca.cfg['common']['workspace'])
    tokens = {}
    if os.path.exists(token_store):
        tokens = json.loads(open(token_store, 'r').read())
    tokens[fqdn] = token
    open(token_store, 'w').write(json.dumps(tokens))

    template_data = open(template_file, 'r').read()
    template = mako.template.Template(template_data)
    cfg_data = template.render(
        server_host='10.42.15.17',
        server_port=4392,
        client_token=token,
    )
    return cfg_data


@bottle.post('/autosign/servers')
@validate_request
def sign_servers_cert():
    srcip = bottle.request.remote_addr
    raw_data = bottle.request.body.read()
    data = json.loads(raw_data)

    if 'fqdn' not in data:
        warning('No fqdn found in request from {0}'.format(srcip))
        return bottle.HTTPResponse(status=403)
    fqdn = data['fqdn']

    if 'csr' not in data:
        warning('No csr found in request from {0}'.format(srcip))
        return bottle.HTTPResponse(status=403)
    csr_data = data['csr']

    csr = '{0}/csr/{1}.csr'.format(ca.ca['basedir'], cfhost(fqdn))
    open(csr, 'w').write('{0}\n'.format(csr_data))

    if not valid_csr(ca, csr, fqdn=fqdn):
        return bottle.HTTPResponse(status=403)

    crt = '{0}/certs/{1}.pem'.format(ca.ca['basedir'], cfhost(fqdn))
    ca.autosign(csr, crt)

    certificate = open(crt, 'r').read()
    return certificate


@bottle.route('/autosign/servers', method='delete')
@validate_request
def revoke_certificate():
    srcip = bottle.request.remote_addr
    raw_data = bottle.request.body.read()
    data = json.loads(raw_data)

    if 'fqdn' not in data:
        warning('No fqdn found in request from {0}'.format(srcip))
        return bottle.HTTPResponse(status=403)
    fqdn = data['fqdn']

    if 'crt' not in data:
        warning('No certificate data found in request from {0}'.format(srcip))
        return bottle.HTTPResponse(status=403)
    crt_data = data['crt']

    ## Save the certificate to be revoked for later usage
    try:
        fd = mkstemp(prefix=C_TMPDIR)
    except OSError, e:
        warning('Error creating temporary file: {0}'.format(e))
        return bottle.HTTPResponse(status=403)
    fd.write(crt_data)
    fd.close()

    ## Revoke the certificate
    ca.revoke(fd.name)

    ### Close the file descriptor towards the temporary certificate
    os.unlink(fd.name)

    info('Revoked the certificate for {0}'.format(fqdn))


def run(host='localhost', port=4392):
    bottle.run(host=host, port=port, fast=True)
