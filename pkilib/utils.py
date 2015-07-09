"""
.. module:: utils
   :platform: Unix, VMS
   :synopsis: Module containing various useful functions

.. moduleauthor:: Lex van Roon <r3boot@r3blog.nl>
"""

import os
import shlex
import subprocess

C_OSNAME = os.uname()[0]


def fpath(name):
    """Helper function which converts a unix path to a vms path, but only
    if the function is called under vms. If it running on any other platform,
    return the original name. The pathname returned will be in DDCU
    format, eg:

    >>> fpath('/some')
    some:
    >>> fpath('/some/file.txt')
    some:file.txt
    >>> fpath('/some/path/under/unix/file.txt')
    some:[path.under.unix]file.txt

    :param name:    Pathname to convert
    :type  name:    str
    :returns:       The converted path
    :rtype:         str
    """
    # Deal with corner cases
    if not isinstance(name, str):
        return ''
    elif name == '':
        return ''
    elif C_OSNAME != 'OpenVMS':
        return name

    # Are we dealing with a single file?
    if '/' not in name:
        return name

    # Start parsing the path
    components = name.split('/')[1:]
    num_components = len(components)

    ddcu = None

    if num_components == 1:
        device = components[0]
        ddcu = '{0}:'.format(device)
    elif num_components == 2:
        device = components[0]
        if '.' in components[1]:
            fname = components[1]
            ddcu = '{0}:{1}'.format(device, fname)
        else:
            path = components[1]
            ddcu = '{0}:[{1}]'.format(device, path)
    else:
        device = components[0]
        path = '.'.join(components[1:num_components-1])
        fname = components[num_components-1]
        ddcu = '{0}:[{1}]{2}'.format(device, path, fname)
    return ddcu


def fhost(name):
    """Helper function which converts a Fully-Qualified Domain Name to a name
    suitable to be used on a vms filesystem. It does this by replacing all
    dots in the name to underscores, thereby allowing the file to have an
    extension, even on ODS-2 filesystems.

    >>> fhost('some.host.name')
    some_host_name

    :param name:    Fully-Qualified Domain Name to convert
    :type  name:    str
    :returns:       The converted fqdn
    :rtype:         str
    """

    # Deal with corner cases
    if not isinstance(name, str):
        return ''
    elif C_OSNAME != 'OpenVMS':
        return name

    return name.replace('.', '_')


def run(cmd, stdout=False):
    """Helper function around subprocess.Popen which can run commands. This
    uses the PATH environment variable used in your shell, so you can choose
    between specifying full or relative commands.

    >>> output = run('uname -s')
    >>> output
    Linux
    >>> run('uname -s', stdout=True)
    Linux

    :param cmd:     Command and parameters to run
    :type  cmd:     str
    :param stdout:  When set to true, display stdout instead of capturing it
    :returns:       Output of command if stdout=False, else None
    :rtype:         str, None
    """
    # Deal with corner cases
    if isinstance(cmd, str):
        if len(cmd) == 0:
            return None
        cmd = shlex.split(cmd)
    elif isinstance(cmd, list):
        pass
    else:
        return None

    output = None
    if stdout:
        proc = subprocess.Popen(cmd)
        proc.wait()
    else:
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
        except FileNotFoundError:
            return None
        proc.wait()
        output = proc.communicate()[0].decode('utf-8')
    return output


if __name__ == '__main__':
    print(run('uname -s'))
