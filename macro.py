"""
I think the whole point about this exercises is

 - think about difference between representation of data and data
 - XORing
"""

import binascii
import base64


# return an byte iterable from an hexadecimal representation
decode = lambda x: bytearray(binascii.a2b_hex(x))

# return a hex "visual" representation by string of "x"
# ENCODING: is the process by which information from a source is converted into symbols to be communicated.
#           in our case we are trasmitting using ASCII/Base64 the binary data
encode = lambda x: binascii.b2a_hex(x)

# return a representation of the XORing of two binary hexadecimal representation
def xor(text, key):
    """XORs a hexadecimal representation of a text.
    
    The text dominates over key so that the lengths don't match we can choose"""
    len_text = len(text)
    len_key = len(key)

    modifier = 1
    if len_key != len_text:
        modifier = int((len_key/len_text) + len_text)

    new_key = key*modifier

    #import pdb;pdb.set_trace()

    return bytes([
        x^y for (x,y) in zip(
            text,
            new_key[:len_text])
        ])

_challenge_count = 0
def challenge(x):
    def _inner():
        global _challenge_count

        _challenge_count += 1
        count = _challenge_count

        print('[+] challenge %d' % count)
        x()
    return _inner

# Cooking MC's like a pound of bacon
def is_ascii(x):
    d = bytearray(b'''!,.(){}[]<>:; 0123456789abcdefgyhilmnopqrstuwvxzjkABCDEFGHILMNOPQRSTUXVWZJKY\'"\n\t''')
    # python3 filter changed behaviour, now returns an iterable
    xx = bytes(list(filter(lambda z:  z in d, x)))
    return xx == x

def how_much_is_actually_english(phrase):
    """Return a metric about the reality of the text be composed of english words

    Since it's not possible to absolutely understand if a piece of text is
    completely english (or human created) is better to create a score system.

    The score goes from 0 to 100 with 0 not english and 100 "we think it's very probably
    english text".
    """
    return 100

def break_one_char_xor(text, threshold):
    results = []
    for c in range(256):
        #print('  [D] key: %02x' % c)
        xored = xor(text, decode(bytes('%02x' % c, 'utf8')))

        #print('  [D] \'%s\'' % xored)

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

def transpose(block, size):
    for idx in range(0, size):
        result = []
        for idx_bis in range(idx, len(block), size):
            result.append(block[idx_bis])

        yield bytearray(result)
