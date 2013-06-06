"""
I think the whole point about this exercises is

 - think about difference between representation of data and data
 - XORing

For the dictionary we need NLTK and wordnet

    >>> import nltk
    >>> nltk.donwload()

and chose "download" and then "wordnet".

"""

import binascii
import base64


# return an byte iterable from an hexadecimal representation
decode = lambda x: bytearray(binascii.a2b_hex(x))

# return a hex "visual" representation by string of "x"
# ENCODING: is the process by which information from a source is converted into symbols to be communicated.
encode = lambda x: binascii.b2a_hex(x)

# return a representation of the XORing of two binary hexadecimal representation
def xor(text, key):
    """The text dominates over key so that the lengths don't match we can choose"""
    len_text = len(text)
    len_key = len(key)

    modifier = 1
    if len_key != len_text:
        modifier = (len_key/len_text) + len_text

    return "".join([
        '%02x' % (x^y,) for (x,y) in zip(
            decode(text),
            (decode(key)*modifier)[:len_text])
        ])

_challenge_count = 0
def challenge(x):
    def _inner():
        global _challenge_count

        _challenge_count += 1
        count = _challenge_count

        print '[+] challenge %d' % count
        x()
    return _inner


def is_ascii(x):
    # TODO: more reliable check for not ascii but plausible (e.g. \n)
    xx = str(bytearray(filter(lambda z: 0x20 <= z < 0x7f or z == 0x0a, x)))
    return xx == x

def how_much_is_actually_english(phrase):
    """Return a metric about the reality of the text be composed of english words

    Since it's not possible to absolutely understand if a piece of text is
    completely english (or human created) is better to create a score system.

    The score goes from 0 to 100 with 0 not english and 100 "we think it's very probably
    english text".
    """
    from nltk.corpus import wordnet

    words = phrase.split(' ')
    check = lambda x: wordnet.synsets(x)

    return float(len(filter(check, words)))/float(len(words))*100

def break_one_char_xor(text, threshold):
    results = []
    for c in range(256):
        xored = decode(xor(text, '%02x' % c))

        if is_ascii(xored) and how_much_is_actually_english(str(xored)) > threshold:
            results.append(xored)

    return results

def hamming_distance(a, b):
    """Calculate the difference between two strings"""

    result = 0
    for x, y in zip(bytearray(a), bytearray(b)):
        # we create a string removing the '0b' part
        bx = bin(x)[2:]
        by = bin(y)[2:]

        lenbx = len(bx)
        lenby = len(by)

        if lenbx < lenby:
            bx , by = by, bx

        # bx > by
        # we add a number of "0" much as missing
        for count in range(abs(lenbx - lenby)):
            by = '0' + by

        for _bx, _by in zip(bx, by):
            if _bx != _by:
                result += 1

    return result

# http://stackoverflow.com/questions/312443/how-do-you-split-a-list-into-evenly-sized-chunks-in-python
def chunks(l, n):
    """ Yield successive n-sized chunks from l.
    """
    for i in xrange(0, len(l), n):
        yield l[i:i+n]
