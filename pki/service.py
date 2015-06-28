
import bottle
import json

from pki.logging    import *

ca =  None

@bottle.get('/')
def index():
    return 'PKI api service\n'

@bottle.post('/autosign/servers')
def sign_servers_cert():
    raw_data = bottle.request.body.read()
    data = json.loads(raw_data)

    csr = '{0}/csr/{1}.csr'.format(ca.ca['basedir'], data['fqdn'])
    crt = '{0}/certs/{1}.pem'.format(ca.ca['basedir'], data['fqdn'])
    print(csr)

    open(csr, 'w').write('{0}\n'.format(data['csr']))
    ca.autosign(csr, crt)

    certificate = open(crt, 'r').read()
    return certificate

def run(host='localhost', port=4392):
    bottle.run(host=host, port=port)
