from macro import (
    guess_keysize,
    matrixify,
    transpose,
    break_one_char_xor,
)

import sys
import logging


logger = logging.getLogger(__name__)


def break_code(code):
    print(' [I] size: %d' % len(code))

    keys = guess_keysize(code)

    logger.debug('keys: %s' % '\n'.join(['%d: %f' % (x[0], x[1]) for x in keys]))

    # loop over keysizes
    for key in keys:
        probable_keysize = key[0]

        print(' [+] use key size: %d' % probable_keysize)

        # create a matrix of probable_keysize columns
        m = list(matrixify(code, probable_keysize))

        print(len(m))

        # now break "keysize" times the XOR with one byte key
        breaked = []
        key_found = []
        for column in transpose(m):
            # print('  [I]: \'%d\'' % len(column))
            result = break_one_char_xor(column)
            breaked.append(result[0][1])
            key_found.append(result[0][2])

        key_found = ''.join([_.decode('ascii') for _ in key_found])
        print(' [+] key: "%s"' % key_found)

        m = transpose(breaked)

        result = b''.join(m)

        logger.info(result)

def usage(progname):
    print('usage: %s <ciphertext>' % progname)
    sys.exit(-1)

if __name__ == '__main__':
    if len(sys.argv) < 2:
        usage(sys.argv[0])

    print(break_code(bytes(sys.argv[1], 'utf-8')))
