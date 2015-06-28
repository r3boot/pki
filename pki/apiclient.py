
import jinja2
import json
import os
import requests

from pki.logging    import *
from pki.parent     import Parent


class APIClient(Parent):
    def __init__(self, config):
        self._cfg = config
        self._api_base = config['api']['url']
        self._s = requests.session()

    def _serialize(self, data):
        return json.dumps(data)

    def _request(self, method, path, payload={}):
        response = {}
        url = self._api_base + path
        r = None
        if payload:
            payload = self._serialize(payload)
        try:
            if method == 'get':
                r = self._s.get(url)
            elif method == 'post':
                r = self._s.post(url, data=payload)
            elif method == 'delete':
                r = self._s.delete(url, data=payload)
            else:
                error('Invalid request method')
        except requests.exceptions.ConnectionError, e:
            error(e)
        finally:
            if not r:
                response = {'result': False, 'content': 'Unknown error'}
            elif r.status_code == 200:
                response = {'result': True, 'content': r.content}

        return response

    def get(self, path, payload={}):
        return self._request('get', path, payload)

    def post(self, path, payload={}):
        return self._request('post', path, payload)

    def delete(self, path, payload={}):
        return self._request('delete', path, payload)

    def new_server_cert(self, fqdn):
        san = fqdn.split('.')[0]
        path = '/servers'
        key = '{0}/private/{1}.key'.format(self._cfg['api']['basedir'], fqdn)
        cfg = '{0}/cfg/{1}.cfg'.format(self._cfg['api']['basedir'], fqdn)
        csr = '{0}/csr/{1}.csr'.format(self._cfg['api']['basedir'], fqdn)
        crt = '{0}/certs/{1}.pem'.format(self._cfg['api']['basedir'], fqdn)

        template_file = '{0}/templates/tls-server-request.cfg.j2'.format(self._cfg['appdir'])
        template_data = open(template_file, 'r').read()
        template = jinja2.Template(template_data)
        cfg_data = template.render(fqdn=fqdn, san=san, certs=self._cfg['certs'])
        open(cfg, 'w').write(cfg_data)

        cmdline = 'openssl req -new -config {0} -out {1} -keyout {2}'.format('{0}/cfg/{1}.cfg'.format(self._cfg['api']['basedir'], fqdn), csr, key)
        proc = self.run(cmdline)
        proc.communicate()

        csr_data = open(csr, 'r').read()
        payload = {
            'fqdn': fqdn,
            'csr': csr_data,
            'token': self._cfg['api']['token'],
        }
        response = self.post(path, payload=payload)
        if not response['result']:
            error('Failed to retrieve a certificate: {0}'.format(response['content']))

        print("writing new certificate to '{0}'".format(crt))
        open(crt, 'w').write(response['content'])
