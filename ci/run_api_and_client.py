#!/usr/bin/env python

import os
import shlex
import subprocess
import sys
import threading
import time


def info(message):
    print('[+] {0}'.format(message))


def error(message):
    print('[E] {0}'.format(message))
    sys.exit(1)


class PKIAPIThread(threading.Thread):
    _proc = None

    def __init__(self, basedir):
        cfg = '{0}/config/pki.yml'.format(basedir)
        logging = '{0}/config/logging.yml'.format(basedir)
        workspace = '{0}/workspace'.format(basedir)
        self._cmd = '{0}/scripts/pkiapi -d -f {1} -l {2} -w {3}'.format(
            basedir, cfg, logging, workspace
        )
        threading.Thread.__init__(self)
        self.setDaemon(True)
        self.start()

    def run(self):
        info('Starting PKI API thread')
        cmd = shlex.split(self._cmd)
        self._proc = subprocess.Popen(cmd)
        self._proc.wait()

    def stop(self):
        if not self._proc:
            return
        try:
            info('Stopping PKI API thread')
            self._proc.kill()
        except ProcessLookupError:
            pass

class PKIClient:
    def __init__(self, basedir):
        workspace = '{0}/workspace'.format(basedir)
        cfg = '{0}/client.yml'.format(workspace)
        logging = '{0}/config/logging.yml'.format(basedir)
        self._cmd = '{0}/scripts/pkiclient -d'.format(basedir)
        self._cmd += ' -u http://127.0.0.1:4392'
        self._cmd += ' -f {0} -l {1} -w {2} -o {2}'.format(
            cfg, logging, workspace
        )

    def generate(self):
        cmd = '{0} newcert'.format(self._cmd)
        cmd = shlex.split(cmd)
        proc = subprocess.Popen(cmd)
        proc.wait()
        proc.communicate()

    def revoke(self):
        cmd = '{0} revoke'.format(self._cmd)
        cmd = shlex.split(cmd)
        proc = subprocess.Popen(cmd)
        proc.wait()
        proc.communicate()


if __name__ == '__main__':
    basedir = os.getcwd()

    workspace = '{0}/workspace'.format(os.getcwd())
    if not os.path.exists(workspace):
        error('{0} does not exist'.format(workspace))

    info('Initializing PKI API')
    pkiapi = PKIAPIThread(basedir)

    info('Waiting till api has started up')
    time.sleep(1.0)

    info('Initializing PKI client')
    pkiclient = PKIClient(basedir)

    info('Requesting new certificate')
    pkiclient.generate()

    info('Revoking certificate')

    pkiapi.stop()
