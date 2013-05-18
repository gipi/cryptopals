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

# return a "visual" representation by string of "x"
encode = lambda x: str(bytearray(x))

# return a representation of the XORing of two binary hexadecimal representation
xor = lambda x,y: "".join(['%02x' % (x^y,) for (x,y) in zip(decode(x), decode(y))])

def challenge1():
    # why "in" give me error?
    _in  = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    out = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'

    assert base64.b64encode(decode(_in)) == out

def challenge2():
    a = '1c0111001f010100061a024b53535009181c'
    b = '686974207468652062756c6c277320657965'
    result = '746865206b696420646f6e277420706c6179'

    assert xor(a, b) == result

def is_ascii(x):
    xx = str(bytearray(filter(lambda z: 0x20 <= z < 0x7f , x)))
    return xx == x

def how_much_is_actually_english(phrase):
    """Return a metric about the reality of the text be composed of english words

    The score goes from 0 to 100 with 0 not english and 100 "we think it's very probably
    english text".

    Since it's not possible to absolutely understand if a piece of text is
    completely english (or human created) is better to create a score system.
    """
    from nltk.corpus import wordnet

    words = phrase.split(' ')
    check = lambda x: wordnet.synsets(x)

    return float(len(filter(check, words)))/float(len(words))*100


def challenge3():
    a = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
    len_a = len(a)

    for c in range(256):
        xored = decode(xor(('%02x' % c) * len_a, a))

        if is_ascii(xored) and how_much_is_actually_english(str(xored)) > 50:
            print xored

challenge1()
challenge2()
challenge3()
