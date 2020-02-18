import base64
from Crypto.Random import random


def find_multiple_occurences_positions(msg, chunk_size):
    """Returns a dictionary with the occurence of the chunks."""
    idxs = {}
    old_chunks = set()
    for chunk in chunks(msg, chunk_size):
        if chunk in old_chunks:
            continue

        old_chunks.add(chunk)

        chunk_ids = []
        tmp_msg = msg[:]
        while True:
            match = tmp_msg.find(chunk)
            if match == -1:
                idxs[chunk] = chunk_ids
                break

            chunk_ids.append(match)

            tmp_msg = tmp_msg[match + 1:]

    return idxs


def find_multiple_occurences(msg, chunk_size):
    positions = find_multiple_occurences_positions(msg, chunk_size)

    for key, value in positions.items():
        positions[key] = len(value)

    return positions


def _is_there_block_with_more_than_one_repetition(message, block_size):
    m = find_multiple_occurences(message, block_size)
    return len(list(filter(lambda x: x > 1, list(m.values())))) > 0


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
