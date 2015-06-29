import re

def valid_fqdn(fqdn):
    ## Matches valid hostnames based on RFC1123
    r = re.compile('^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$')

    result = r.search(fqdn)
    return result != None
