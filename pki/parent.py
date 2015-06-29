
import shlex
import subprocess

from pki.logging    import *

class Parent:
    def run(self, cmd, stdin=False, stdout=False):
        cmd = shlex.split(cmd)

        if stdout:
            if stdin:
                proc = subprocess.Popen(cmd, stdin=subprocess.PIPE)
            else:
                proc = subprocess.Popen(cmd)
        else:
            if stdin:
                proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            else:
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return proc
