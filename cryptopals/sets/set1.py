import base64

from ..macro import (
    bitsencode,
    hexdecode,
    hexencode,
    break_one_char_xor,
    xor,
)
from .. import break_vigenere
from ..utils import decodeBase64file, _is_there_block_with_more_than_one_repetition
from ..meta import cryptopals
from ..ecb import aes_ecb_encrypt, aes_ecb_decrypt


@cryptopals.challenge(1, 1, 'Convert hex to base64')
def challenge1():
    '''Simple exercise in converting an hexadecimal representation to base64'''
    inp = b'49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    out = b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
    encoded = base64.b64encode(hexdecode(inp))
    assert encoded == out

    print(f'{inp} -> {encoded}')


@cryptopals.challenge(1, 2, 'Fixed XOR')
def challenge2():
    """Here we take two decoded binary data representation and xoring them
    and check with another decoded binary data
    """
    a = b'1c0111001f010100061a024b53535009181c'
    b = b'686974207468652062756c6c277320657965'
    result = b'746865206b696420646f6e277420706c6179'

    assert xor(hexdecode(a), hexdecode(b)) == hexdecode(result), xor(hexdecode(a), hexdecode(b))

    print(bitsencode(hexdecode(a)))
    print(bitsencode(hexdecode(b)))
    print('-' * len(a) * 4, 'XOR')
    print(bitsencode(hexdecode(result)))


@cryptopals.challenge(1, 3, 'Single-byte XOR cipher')
def challenge3():
    '''Break XOR cypher using one byte key.

Internally it uses a scoring method in order to recognize english looking text.'''
    a = b'1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
    results = break_one_char_xor(hexdecode(a), 99)

    score, text, key = results[0]

    print(f'The most promising solution is \'{text.decode()}\' with a score of {score}; the corresponging key is \'{key.decode()}\'')


@cryptopals.challenge(1, 4, 'Detect single-character XOR')
def challenge4():
    '''With the technique from challenge 3 we should find something single-character XORed'''
    _in = []
    with open('challenge4.txt', 'r') as f:
        for line in f:
            _in.append(line.strip())

    results = {}
    for text in _in:
        print(f'\rNow analyzing ciphertext {text}', end='')
        score, text, key = break_one_char_xor(hexdecode(text), 1)[0]
        results[text] = (score, key)

    # clean up the line
    print('\r'),

    best_text_fit = None
    best_score = float('inf')
    best_key = None

    for key in results:
        if best_score > results[key][0]:
            best_score = results[key][0]
            best_text_fit = key
            best_key = results[key][1]

    print(f'> The decyphered text is \'{best_text_fit.decode()}\' with key \'{best_key.decode()}\'')


@cryptopals.challenge(1, 5, 'Implement repeating-key XOR')
def challenge5():
    '''Implementation of a repeating-key XOR cipher.'''
    key = b'ICE'
    _in = b"""Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"""
    ciphertext = xor(_in, key)
    assert hexencode(ciphertext) \
        == b'0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'

    print(bitsencode(_in)[:40])
    print((bitsencode(key) * (len(_in) // len(key)))[:40])
    print('-' * 40)
    print(bitsencode(ciphertext)[:40])


@cryptopals.challenge(1, 6, 'Break repeating-key XOR')
def challenge6():
    '''Now we are going to break a repeating-key XOR: it's not
difficult, first of all you have to find the key length via minimization
of the Hamming distance, then you can organize the ciphertext in chunk
of KEYSIZE columns and break each column as a single-byte XOR cipher'''
    # https://gist.github.com/tqbf/3132752/raw/cecdb818e3ee4f5dda6f0847bfd90a83edb87e73/gistfile1.txt
    code = decodeBase64file('challenge6.txt')

    results = break_vigenere.break_code(code, count=3)
    most_probable = results[list(results.keys())[0]]

    print(f'The most probable plaintext is \'{most_probable["plaintext"].decode()}\' with key \'{most_probable["key"]}\'')

# _sets = [(x[0][1],x[1][1], x[2][1]) for x in breaked]
#        permutation_sets = product(_sets)
#        for x in permutation_sets:
#            m = transpose(x)
#            print(b''.join(m)[:50])
#            print()


@cryptopals.challenge(1, 7, 'AES in ECB mode')
def challenge7():
    cyphertext = decodeBase64file('challenge7.txt')

    key = b"YELLOW SUBMARINE"
    plaintext = aes_ecb_decrypt(cyphertext, key)
    print(f'plaintext: \'{plaintext.decode()}\'', )


@cryptopals.challenge(1, 8, 'Detect AES in ECB mode')
def challenge8():
    cyphertexts = []
    with open('challenge8.txt', 'rb') as f:
        # remove the '\n' part
        cyphertexts = list([x[:-1] for x in f.readlines()])

    for cyphertext in cyphertexts:
        if _is_there_block_with_more_than_one_repetition(cyphertext, 16):
            print(' [+] found probably ECB: \'%s\'' % cyphertext)
