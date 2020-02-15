from .macro import (
    guess_keysize,
    matrixify,
    transpose,
    break_one_char_xor,
)

import sys
import logging


logger = logging.getLogger(__name__)


def break_code(code, count=10):
    logger.debug('ciphertext size: %d' % len(code))

    keys = guess_keysize(code)

    logger.debug('keys: %s' % '\n'.join(['%d: %f' % (x[0], x[1]) for x in keys]))

    results = {}

    # loop over keysizes
    for key, _ in zip(keys, range(count)):
        probable_keysize = key[0]

        logger.debug('key size: %d' % probable_keysize)

        # create a matrix of probable_keysize columns
        m = list(matrixify(code, probable_keysize))

        # now break "keysize" times the XOR with one byte key
        breaked = []
        key_found = []
        for column in transpose(m):
            result = break_one_char_xor(column)
            breaked.append(result[0][1])
            key_found.append(result[0][2])

        key_found = ''.join([_.decode('ascii') for _ in key_found])
        logger.debug('key: "%s"' % key_found)

        m = transpose(breaked)

        result = b''.join(m)

        logger.debug(result)
        results[probable_keysize] = {
            'key_score': key[1],
            'key': key_found,
            'plaintext': result,
        }

    return results


def usage(progname):
    print('usage: %s <ciphertext>' % progname)
    sys.exit(-1)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        usage(sys.argv[0])

    print(break_code(bytes(sys.argv[1], 'utf-8')))
