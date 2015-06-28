
from Crypto.Hash    import SHA256
import bottle
import json
import os
import random
import socket

from pki.logging    import *

ca =  None

def validate_fqdn(srcip, fqdn):
    data = socket.getaddrinfo(fqdn, 80)
    fqdn_ips = []
    for item in data:
        ip = item[4][0]
        if ip not in fqdn_ips:
            fqdn_ips.append(ip)

    if srcip in fqdn_ips:
        return True
    else:
        warning('fqdn does not match ip address of request')
        return True

def validate_token(fqdn, token):
    token_store = '{0}/tokens.json'.format(ca.cfg['common']['basedir'])
    if not os.path.exists(token_store):
        warning('{0} does not exist'.format(token_store))
        return False
    tokens = json.loads(open(token_store, 'r').read())
    if fqdn not in tokens:
        warning('{0} does not have a token'.format(fqdn))
        return False
    elif tokens[fqdn] == token:
        return True
    else:
        warning('token mismatch for {0}'.format(fqdn))
        return False

@bottle.get('/')
def index():
    return 'PKI api service\n'

@bottle.get('/test/<fqdn>')
def test_fqdn(fqdn):
    if validate_fqdn(bottle.request.remote_addr, fqdn):
        return 'ok'
    else:
        return bottle.HTTPResponse(status=403, body='Not authenticated')

@bottle.get('/token/<fqdn>')
def generate_token(fqdn):
    token_store = '{0}/tokens.json'.format(ca.cfg['common']['basedir'])
    seed = random.random()
    raw_token = '{0}{1}'.format(seed, fqdn)
    sha = SHA256.new()
    sha.update(raw_token)
    token = sha.hexdigest()
    tokens = {}
    if os.path.exists(token_store):
        tokens = json.loads(open(token_store, 'r').read())
    tokens[fqdn] = token
    open(token_store, 'w').write(json.dumps(tokens))
    return token

@bottle.post('/autosign/servers')
def sign_servers_cert():
    raw_data = bottle.request.body.read()
    data = json.loads(raw_data)

    if not validate_fqdn(bottle.request.remote_addr, data['fqdn']):
        return bottle.HTTPResponse(status=403)

    if not validate_token(data['fqdn'], data['token']):
        return bottle.HTTPResponse(status=403)

    csr = '{0}/csr/{1}.csr'.format(ca.ca['basedir'], data['fqdn'])
    crt = '{0}/certs/{1}.pem'.format(ca.ca['basedir'], data['fqdn'])

    open(csr, 'w').write('{0}\n'.format(data['csr']))
    ca.autosign(csr, crt)

    certificate = open(crt, 'r').read()
    return certificate

def run(host='localhost', port=4392):
    bottle.run(host=host, port=port)
