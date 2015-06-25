
import json
import os

from pki.logging    import *

def load_config(filename):
    if not os.path.exists(filename):
        error('{0} does not exist'.format(filename))
    raw_data = open(filename, 'r').read()
    try:
        data = json.loads(raw_data)
    except ValueError, e:
        error('Failed to parse json: {0}'.format(e))
    return data
