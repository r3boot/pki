"""
... module:: root
    :platform: Unix, VMS
    :synopsis: Class representing a Root CA

.. moduleauthor:: Lex van Roon <r3boot@r3blog.nl>
"""

import os

from pkilib import log
from pkilib import ca


class RootCA(ca.ParentCA):
    """ RootCA:     Class implementing the root CA

    :param config:  Dictionary containing the contents of the config file
    :type  config:  str
    """
    ca_type = ca.CA_ROOT
    ca_data = {}

    def __init__(self, config):
        """ __init__:       Initialize RootCA class

        @param:     config  Dictionary containing the contents of the
                            configuration file
        """
        ca.ParentCA.__init__(self, config)

    def initca(self, pwfile=None):
        """ initca:     Generate the key and certificate for this CA
        """
        if pwfile and not os.path.exists(pwfile):
            log.warning('{0} does not exist'.format(pwfile))
            return False

        log.info('Generating key and csr for {0} CA'.format(self.name))
        self.genkey(
            self.ca_data['cfg'],
            self.name,
            pwfile
        )

        log.info('Generating certificate for {0} CA'.format(self.name))
        self.selfsign(
            self.ca_data['cfg'],
            self.name,
            pwfile,
        )
