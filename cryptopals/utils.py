import base64
from Crypto.Random import random


def decodeBase64file(filepath):
    filecontents = ""
    with open(filepath, 'rb') as f:
        filecontents = base64.b64decode(f.read())

    return filecontents


# http://stackoverflow.com/questions/312443/how-do-you-split-a-list-into-evenly-sized-chunks-in-python
def chunks(l, n):
    """ Yield successive n-sized chunks from l.
    """
    for i in range(0, len(l), n):
        yield l[i:i + n]


def generate_random_bytes(count):
    return b''.join([bytes([random.getrandbits(8)]) for x in range(count)])


def adjacent_chunks(l, n):
    for i in range(0, len(l) - (n - 1)):
        yield l[i:i + n]
