"""
.. module:: tokens
   :platform: Unix, VMS
   :synopsis: Class wrapping around a simple token store

.. moduleauthor:: Lex van Roon <r3boot@r3blog.nl>
"""
import json
import os
import re

import pkilib.log as log
import pkilib.utils as utils
import pkilib.server.checks as checks


class TokenStore(object):
    """Class representing a json backingstore based token store. Declare a
    new instance as follows:

    >>> store = TokenStore('/path/to/tokens.json')
    >>> store.load()

    :param store:   Path to token store
    :type  str:     str
    """
    def __init__(self, store):
        self._backingstore = store
        self._store = {}

    @staticmethod
    def validate_store(data=None):
        """This function will validate if the list specified in data
        represents a correct tokenstore list. The format of this list is as
        follows::

        {'<fqdn>': '<token>'}

        Use it in the following manner:

        >>> store_data = {'some.host.name': '<hex64 string>'}
        >>> validate_store(store_data)
        True

        This function will return True if the data matches the above format,
        and False if it does not.

        :param data:    List containing the token store
        :rtype data:    list
        :returns:       True if data is a valid token store, else False
        :rtype:         bool
        """
        if data is None:
            log.warning('data cannot be None')
            return False
        if not isinstance(data, dict):
            log.warning('data needs to be a dictionary')
            return False

        regexp = re.compile('[0-9a-f]{64,64}')

        for fqdn, token in data.items():
            if not checks.valid_fqdn(fqdn):
                return False
            if token is None or not isinstance(token, str):
                log.warning('Token needs to be a string')
                return False
            if regexp.search(token) is None:
                log.warning('Invalid token supplied')
                return False

        return True

    def load(self):
        """Read the backingstore from disk. The backingstore must point to a
        valid file. It will return True if this succeeds, or False in one of
        the following conditions:

        - Backing store points to an invalid path
        - Backing store data could not be parsed to json
        - Backing store data does not match the expected format

        :returns:   True if loading succeeded, False if not
        :rtype:     bool
        """
        if self._backingstore is None:
            log.warning('backingstore cannot be None')
            return False
        if not isinstance(self._backingstore, str):
            log.warning('backingstore needs to be a string')
            return False
        if not os.path.exists(self._backingstore):
            log.debug('No backingstore found, using defaults')
            return True

        raw_data = open(self._backingstore, 'r').read()
        try:
            data = json.loads(raw_data)
        except (TypeError, ValueError):
            log.warning('backing store needs to contain json data')
            return False

        if not self.validate_store(data):
            log.warning('backingstore contains invalid data')
            return False

        self._store = data
        return True

    def save(self):
        """Save the in-memory backing store to disk. It will blindly overwrite
        the backingstore, so use with caution. This function will return False
        if the backingstore points to an invalid file or the in-memory database
        could not be written to disk.

        :returns:   True if saving succeeded, False if it didn't
        :rtype:     bool
        """
        if self._backingstore is None:
            log.warning('backingstore cannot be None')
            return False
        if not isinstance(self._backingstore, str):
            log.warning('backingstore needs to be a string')
            return False

        data = json.dumps(self._store)
        try:
            open(self._backingstore, 'w').write(data)
        except EnvironmentError as err:
            log.warning('Failed to update backing store: {0}'.format(err))
            return False
        return True

    def get(self, fqdn):
        """Helper function to lookup an fqdn in the in-memory database. It will
        return the token if it is found, or False if the fqn is invalid or
        there is no token for fqdn

        :param fqdn:    Fully-Qualified Domain-Name of host to lookup
        :type  fqdn:    str
        :returns:       Token for fqdn, or False if an error occurred
        :rtype:         str, bool
        """
        if not checks.valid_fqdn(fqdn):
            log.debug('invalid fqdn')
            return False
        if fqdn not in self._store:
            log.debug('fqdn not defined')
            return False
        return self._store[fqdn]

    def new(self, fqdn):
        """Generates a new token for a fqdn if it does not yet exist and
        return it. This function will return False if the fqdn is invalid or
        if the token already exists

        :param fqdn:    Fully-Qualified Domain-Name for the host
        :type  fqdn:    str
        :returns:       Token for the new host, or False if an error occurred
        :rtype:         str, bool
        """
        if not checks.valid_fqdn(fqdn):
            return False
        if self.get(fqdn):
            log.warning('Token for {0} already exists'.format(fqdn))
            return False
        token = utils.gentoken()
        self._store[fqdn] = token
        self.save()
        return token

    def validate(self, fqdn, token):
        """Check if fqdn is defined in the in-memory token store and if the
        stored token matches the supplied token. It will return True if the
        fqdn has a token in the store, and this matches the supplied token.
        It will return False if the fqdn or token is invalid.

        :param fqdn:    Fully-Qualified Domain-Name of the host
        :type  fqdn:    str
        :param token:   Token to validate
        :type  token:   str
        :returns:       True if the fqdn/token pair is found, False if not
        :rtype:         bool
        """
        regexp = re.compile('[0-9a-f]{64,64}')
        if not checks.valid_fqdn(fqdn):
            return False
        if token is None:
            log.warning('token cannot be None')
            return False
        if not isinstance(token, str):
            log.warning('token needs to be a string')
            return False
        if regexp.search(token) is None:
            log.warning('token needs to be a valid hex64 string')
            return False

        return token == self.get(fqdn)
