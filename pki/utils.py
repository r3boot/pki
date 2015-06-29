from Crypto.Hash    import SHA256

import random


def gentoken():
    sha = SHA256.new()
    sha.update(str(random.random()))
    return sha.hexdigest()
