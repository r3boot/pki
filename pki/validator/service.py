
from Crypto.Hash    import SHA256

import json
import random
import socket
import threading
import requests

from pki.logging    import *
from pki.utils      import *
from pki            import bottle

class MyWSGIRefServer(bottle.ServerAdapter):
    server = None

    def run(self, handler):
        from wsgiref.simple_server import make_server, WSGIRequestHandler
        if self.quiet:
            class QuietHandler(WSGIRequestHandler):
                def log_request(*args, **kw): pass
            self.options['handler_class'] = QuietHandler
        self.server = make_server(self.host, self.port, handler, **self.options)
        self.server.serve_forever()

    def stop(self):
        self.server.shutdown()


class ValidatorAPI(threading.Thread):
    def __init__(self, host=None, port=None):
        if not host:
            error('ValidateAPI needs a listen ip')
        self.host = host

        if not port:
            error('ValidateAPI needs a listen port')
        self.port = port

        self._app = bottle.Bottle()
        self._server = MyWSGIRefServer(host=host, port=port)
        self._app.route('/validate', method='GET', callback=self.serve_token)
        self.token = gentoken()

        threading.Thread.__init__(self)
        self.setDaemon(True)

    def serve_token(self):
        return self.token

    def initialize_client(self, url, cfg_file, fqdn):
        path = '{0}/token/{1}'.format(url, fqdn)
        payload = json.dumps({ 'token': self.token, })
        info('Sending request for new token')
        r = None
        cfg_data = None
        try:
            r = requests.post(path, data=payload)
        except requests.exceptions.ConnectionError, e:
            error(e)
        finally:
            if not r:
                error('Unknown error trying to request a token')
            elif r and r.status_code != 200:
                error('Unknown return code received from pki')
            else:
                cfg_data = r.content

        info('Received new token, writing configuration to {0}'.format(cfg_file))

        open(cfg_file, 'w').write('{0}\n'.format(cfg_data))

    def run(self):
        try:
            self._app.run(server=self._server)
        except socket.error, e:
            error('Validator failed to start: {0}'.format(e))

    def stop(self):
        self._server.stop()
