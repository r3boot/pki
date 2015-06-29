import requests

from pki.logging    import *

class ValidatorClient:
    def __init__(self, fqdn, port=4393):
        self._url = 'http://{0}:{1}/validate'.format(fqdn, port)

    def validate(self, req_token=None):
        if not req_token:
            warning('validator client needs a request token')
            return
        recv_token = None

        debug('Sending validation request to {0}'.format(self._url))
        r = None
        try:
            r = requests.get(self._url)
        except requests.exceptions.ConnectionError, e:
            warning('Failed to connect to {0}: {1}'.format(self._url, e))
            return
        finally:
            if r and r.status_code == 200:
                recv_token = r.content

        return req_token == recv_token
