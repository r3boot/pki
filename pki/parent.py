
import shlex
import subprocess

from pki.logging    import *

class Parent:
    def run(self, cmd, stdin=None):
        cmd = shlex.split(cmd)
        if stdin:
            proc = subprocess.Popen(cmd, stdin=subprocess.PIPE)
        else:
            proc = subprocess.Popen(cmd)
        return proc
