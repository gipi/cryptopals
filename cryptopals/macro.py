# encoding: utf-8
"""
I think the whole point about this exercises is

- think about difference between representation of data and data
- XORing

    >>> a = b'\\x01'
    >>> type(a)
    <class 'bytes'>
    >>> a[0]
    1
    >>> type(a[0])
    <class 'int'>
    >>> type(a[0:1])
    <class 'bytes'>
    >>> bytes(4)
    b'\\x00\\x00\\x00\\x00'
    >>> bytes([4,])
    b'\\x04'

bytes type is an immutable sequence of integers
bytearray type is a mutable sequence of integers

Bytes and bytearray objects, being “strings of bytes”,
have all methods found on strings, with the exception
of encode(), format() and isidentifier(), which do not
make sense with these types. For converting the objects
to strings, they have a decode() method.

**HERE ALL IS PASSED AS BYTES AND RETURNED AS BYTE**
"""
import binascii
import math
import logging

from .utils import adjacent_chunks, chunks, generate_random_bytes

_DEBUG = False

logging.basicConfig(level=logging.DEBUG)

logger = logging.getLogger(__name__)


# return an byte iterable from an hexadecimal representation
hexdecode = lambda x: bytearray(binascii.a2b_hex(x))


# return a hex "visual" representation by string of "x"
# ENCODING: is the process by which information from a source is converted into symbols to be communicated.
#           in our case we are trasmitting using ASCII/Base64 the binary data
hexencode = lambda x: binascii.b2a_hex(x)


def bitsencode(x):
    '''Return from a bytearray a bits representation

        >>> bitsencode(b'\\x10\\xAA')
        '0001000010101010'

    '''
    return ''.join([f'{_:08b}' for _ in x])


# return a representation of the XORing of two binary hexadecimal representation
def xor(text, key):
    """XORs a text with a key.

    The text dominates over key so that the lengths don't match we can choose

        >>> xor(b'\\x00\\xf0\\x0f\\xff', b'\\x00')
        b'\\x00\\xf0\\x0f\\xff'
        >>> xor(b'\\xf0', b'\\x0f')
        b'\\xff'
    """
    len_text = len(text)
    len_key = len(key)

    modifier = 1
    if len_key != len_text:
        modifier = int((len_key / len_text) + len_text)

    new_key = key * modifier

    return bytes([
        x ^ y for (x, y) in zip(
            text,
            new_key[:len_text])
    ])


# Cooking MC's like a pound of bacon
def is_ascii(x):
    import string
    d = bytearray(b'''!,.(){}[]<>:;*#%?&~+$-_/\\ 0123456789abcdefgyhilmnopqrstuwvxzjkABCDEFGHILMNOPQRSTUXVWZJKY\'"\n\t''')
    # python3 filter changed behaviour, now returns an iterable
    xx = bytes(list(filter(lambda z:  z in bytearray(string.printable, 'utf8'), x)))
    return xx == x


_filter = lambda z, w: list(filter(lambda x: x in bytearray(z, 'utf8'), w))


# frequencies taken from wikipedia
#  http://en.wikipedia.org/wiki/Letter_frequency
ENGLISH_FREQUENCIES = {
    'a':  8.2,
    'b':  1.5,
    'c':  2.8,
    'd':  4.3,
    'e': 12.7,
    'f':  2.2,
    'g':  2.0,
    'h':  6.1,
    'i':  7.0,
    'j':  0.2,
    'k':  0.8,
    'l':  4.0,
    'm':  2.4,
    'n':  6.7,
    'o':  7.5,
    'p':  1.9,
    'q':  0.1,
    'r':  6.0,
    's':  6.3,
    't':  9.1,
    'u':  2.8,
    'v':  1.0,
    'w':  2.4,
    'x':  0.2,
    'y':  2.0,
    'z':  0.1,
}


def how_much_is_actually_english(phrase):
    """Return a metric about the reality of the text be composed of english words

    Since it's not possible to absolutely understand if a piece of text is
    completely english (or human created) is better to create a score system.

    We calculate internally the difference of distribution between occurrence of
    the same letters in a text of same length.

    Lower number is better.
    """
    phrase_length = len(phrase)

    difference = 0.0

    # calculate the difference between expected char count and actual number
    for key in ENGLISH_FREQUENCIES.keys():
        expected_count = (phrase_length * ENGLISH_FREQUENCIES[key]) / 100.0
        count = len(list(filter(lambda x: x in bytearray(key, 'utf8'), phrase)))
        # take into account only the letters actual are here
        if count == 0:
            continue
        difference += abs(expected_count - count)

    # now count how many characters are not in the english alphabet
    not_english_char = len(
        list(
            filter(lambda x: x not in bytearray(''.join(ENGLISH_FREQUENCIES.keys()) + '\n,.\'" ', 'utf8'), phrase)
        )
    )

    return (difference + not_english_char * 10) / phrase_length


def break_one_char_xor(text, threshold=1):
    '''Return a list of possible breaked text ordered with more
    probable first'''
    results = []

    for c in range(256):
        # print('  [D] key: %02x' % c)
        key = bytes('%02x' % c, 'utf8')
        xored = xor(text, hexdecode(key))

        # print('  [D] \'%s\'' % xored)

        score = how_much_is_actually_english(xored)
        # print(xored)
        # print('%s %f vs %f' % (key, min_score, score))

        results.append((score, xored, bytes([c])))

    import operator

    return sorted(results, key=operator.itemgetter(0))[:threshold]


def hamming_distance(a, b):
    """Calculate the difference between two strings counted
    as the number of different bits between them.

    >>> hamming_distance(b'\\x00', b'\\x01')
    1
    >>> hamming_distance(b'this is a test', b'wokka wokka!!!')
    37
    """

    result = 0
    for x, y in zip(bytearray(a), bytearray(b)):
        # we create a string removing the '0b' part
        bx = bin(x)[2:]
        by = bin(y)[2:]

        lenbx = len(bx)
        lenby = len(by)

        if lenbx < lenby:
            bx, by = by, bx

        # bx > by
        # we add a number of "0" much as missing
        for count in range(abs(lenbx - lenby)):
            by = '0' + by

        for _bx, _by in zip(bx, by):
            if _bx != _by:
                result += 1

    return result


def hamming_distance_bis(a, b):
    if len(a) != len(b):
        raise ValueError('the texts have different lengths')
    c = xor(a, b)
    # calculate the number of 1s in the xor of the two texts
    return len(filter(lambda x: x == '1', ''.join([bin(x)[2:] for x in c])))


def guess_keysize(text, start=2, end=41):
    '''Returns an ordered list of probably keysize for a supposed XORed plaintext

    http://crypto.stackexchange.com/questions/8115/repeating-key-xor-and-hamming-distance
    '''
    results = []
    # for each keysize
    for keysize in range(start, end):
        distance = 0
        block_n = int(math.floor(len(text) / keysize))
        # calculate the average hamming distance
        for block_index in range(block_n):
            first_block = text[block_index * keysize:(block_index + 1) * keysize]
            second_block = text[(block_index + 1) * keysize:(block_index + 2) * keysize]
            distance += hamming_distance(first_block, second_block) / keysize

        results.append([keysize, distance / block_n])

    import operator

    return sorted(results, key=operator.itemgetter(1))


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


def matrixify(data, size):
    """Transforms in an array a byte sequence.

        >>> i = b'\\x04\\x01\\x02\\x03'
        >>> i
        b'\\x04\\x01\\x02\\x03'
        >>> list(matrixify(i, 2))
        [b'\\x04\\x01', b'\\x02\\x03']
        >>> list(matrixify(b'\\x00\\x01\\x02\\x03\\x04', 2))
        [b'\\x00\\x01', b'\\x02\\x03', b'\\x04']

    Returns an iterator.
    """
    for idx in range(0, math.ceil(len(data) / size)):
        start_offset = idx * size
        end_offset = start_offset + size

        yield data[start_offset:end_offset]


def transpose(m):
    """Transposes a matrix-like arrangeament of data.

        >>> m = [b'\\x01\\x02\\x03', b'\\x04\\x05\\x06']
        >>> transpose(m)
        [b'\\x01\\x04', b'\\x02\\x05', b'\\x03\\x06']
        >>> transpose(transpose(m)) == m
        True
        >>> m = [b'\\x01\\x02\\x03', b'\\x04\\x05\\x06', b'\\x07']
        >>> transpose(m)
        [b'\\x01\\x04\\x07', b'\\x02\\x05', b'\\x03\\x06']
        >>> m = [b'\\x01\\x02\\x03', b'\\x04\\x05\\x06', b'\\x07\\x08']
        >>> transpose(m)
        [b'\\x01\\x04\\x07', b'\\x02\\x05\\x08', b'\\x03\\x06']
        >>> transpose(transpose(m)) == m
        True
    """
    row_count = len(m)
    row_length = len(m[0])

    new_m = []

    for idx in range(0, row_length):
        new_row = []
        for cidx in range(0, row_count):
            new_row.append(m[cidx][idx:idx + 1])

        # http://stackoverflow.com/questions/17068100/joining-byte-list-with-python
        new_m.append(b''.join(new_row))

    return new_m


def find_frequencies(text, size=1):
    """Return a dictionary containing the frequencies"""
    # FIXME: use binomial
    n = 1

    count = {}
    for c in adjacent_chunks(text, size):
        count[c] = count.get(c, 0.0) + 1.0

    freq = {}
    for k in count.keys():
        freq[k] = count[k] / n

    return freq


def product(l):
    '''Generates all the concatenations from iterable.

        >>> product([('A0', 'A1'), ('B0', 'B1')])
        [['A0', 'B0'], ['A1', 'B0'], ['A0', 'B1'], ['A1', 'B1']]
    '''
    def _from_number_to_digit(base, size, n):
        '''Calculates the list of size n of digits in the given base
        from the number n.

            >>> _from_number_to_digit(2, 3, 2)
        '''
        r = []
        previous = n
        idxs = list(range(size))
        idxs.reverse()
        for x in idxs:
            term = math.pow(base, x)
            digit = int(previous / term)

            r.append(digit)

            previous -= digit * term

        r.reverse()

        return r

    result = []
    _set_size = len(l[0])
    for x in range(int(math.pow(_set_size, len(l)))):
        r = []
        for _set, item_idx in zip(l, _from_number_to_digit(_set_size, len(l), x)):
            r.append(_set[item_idx])

        result.append(r)

    return result


def generate_random_aes_key():
    return generate_random_bytes(16)
