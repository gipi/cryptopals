import base64
import logging

from cryptopals.macro import *
from cryptopals.utils import decodeBase64file
from cryptopals.ecb import aes_ecb_encrypt, aes_ecb_decrypt
from cryptopals.cbc import cbc, aes_cbc_encrypt, aes_cbc_decrypt
from cryptopals import break_vigenere
from cryptopals.meta import cryptopals


CHALLENGE = 5
logging.addLevelName(CHALLENGE, 'CHALLENGE')


def challenge_log(self, message, *args, **kwargs):
    self.log(CHALLENGE, message, *args, **kwargs)


logging.Logger.challenge = challenge_log

logger = logging.getLogger()
logger.setLevel(CHALLENGE)

# http://stackoverflow.com/a/16955098/1935366


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
    key = b'ICE'
    _in = b"""Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"""
    assert encode(xor(_in,
                      key)) == b'0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'


@cryptopals.challenge(1, 6, 'Break repeating-key XOR')
def challenge6():
    # https://gist.github.com/tqbf/3132752/raw/cecdb818e3ee4f5dda6f0847bfd90a83edb87e73/gistfile1.txt
    code = decodeBase64file('challenge6.txt')

    break_vigenere.break_code(code)


# _sets = [(x[0][1],x[1][1], x[2][1]) for x in breaked]
#        permutation_sets = product(_sets)
#        for x in permutation_sets:
#            m = transpose(x)
#            print(b''.join(m)[:50])
#            print()

@cryptopals.challenge(1, 7, 'AES in ECB mode')
def challenge7():
    cyphertext = decodeBase64file('challenge7.txt')

    key = "YELLOW SUBMARINE"

    print(' [+]: ', aes_ecb_decrypt(cyphertext, key))


def _is_there_block_with_more_than_one_repetition(message, block_size):
    m = find_multiple_occurences(message, block_size)
    return len(list(filter(lambda x: x > 1, list(m.values())))) > 0


@cryptopals.challenge(1, 8, 'Detect AES in ECB mode')
def challenge8():
    cyphertexts = []
    with open('challenge8.txt', 'rb') as f:
        # remove the '\n' part
        cyphertexts = list([x[:-1] for x in f.readlines()])

    for cyphertext in cyphertexts:
        if _is_there_block_with_more_than_one_repetition(cyphertext, 16):
            print(' [+] found probably ECB: \'%s\'' % cyphertext)


@cryptopals.challenge(2, 10, 'Implement CBC mode')
def challenge10():
    ciphertext = decodeBase64file('challenge10.txt')

    key = b'YELLOW SUBMARINE'
    iv = b'\x00' * 16

    plaintext = aes_cbc_decrypt(ciphertext, key, iv)

    logger.info('AES-CBC-128: %s' % plaintext)


def encryption_oracle(plaintext):
    key = generate_random_aes_key()
    iv = generate_random_aes_key()

    cypher = None
    if random.getrandbits(1):
        logger.debug("CBC")
        cypher = aes_cbc_encrypt(plaintext, key, iv)
    else:
        logger.debug("ECB")
        cypher = aes_ecb_encrypt(plaintext, key, pad=True)

    return cypher


@cryptopals.challenge(2, 11, 'An ECB/CBC detection oracle')
def challenge11():
    '''The point of this challenge is that if we control the plaintext
    we can take apart ECB from CBC simply using repeated blocks'''
    plaintext = b'''0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'''

    ciphertext = encryption_oracle(generate_random_bytes(5) + plaintext + generate_random_bytes(3))

    tipe = None
    if _is_there_block_with_more_than_one_repetition(ciphertext, 4):
        tipe = 'FOUND ECB'
    else:
        tipe = 'FOUND CBC'

    logger.info(tipe)


@cryptopals.challenge(2, 12, 'Byte-at-a-time ECB decryption (Simple)')
def challenge12():
    secret_encoded_string = '''
    Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
    aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
    dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
    YnkK'''

    secret_string = base64.b64decode(secret_encoded_string)

    n = len(secret_string)

    key = generate_random_aes_key()

    # for count in range(50):
    # 	# use hex representation to have a quick view of length
    # 	logger.info(encode(aes_ecb_encrypt(secret_string + b'A'*count, key, pad=True)))

    guessed = b''
    step = 0

    while len(guessed) < len(secret_string):
        block_number = int(len(guessed) / 16)
        prefix = b'A' * (15 - step % 16)
        # the last byte in the first block is the first byte of the secret string
        first_block = aes_ecb_encrypt(prefix + secret_string, key, pad=True)[block_number * 16:(block_number + 1) * 16]

        for c in range(255):
            if step < 16:
                real_prefix = prefix + guessed
            else:
                base = step - 16 + 1
                end = base + 15
                real_prefix = guessed[base:end]

            guess = aes_ecb_encrypt(real_prefix + bytes([c]), key, pad=False)

            if guess == first_block:
                guessed = guessed + bytes([c])
                step += 1
                break

    logger.info(b'find out secret: ' + guessed)


def parse_cookie(cookie):
    """
        >>> parse_cookie("miao=bau&id=10")
        {'miao': 'bau', 'id': '10'}
    """
    result = {}

    token = cookie.split('&')

    for key, value in [x.split('=') for x in token]:
        result[key] = value

    return result


def encode_cookie(obj):
    '''
        >>> obj = {"email": "foo@bar.com", "uid":10, "role":"admin"}
        >>> encode_cookie(obj)
        'email=foo@bar.com&uid=10&role=admin'
    '''
    return 'email=%(email)s&uid=%(uid)s&role=%(role)s' % obj


def profile_for(email):
    not_allowed = ['&', '=']
    if len(list(filter(lambda x: x in not_allowed, email))) > 0:
        raise ValueError('invalid email address')

    return {
        "email": email,
        "uid": 10,
        "role": "user",
    }


def encrypted_profile(key, email):
    return aes_ecb_encrypt(bytes(encode_cookie(profile_for(email)), 'utf-8'), key, pad=True)


def decrypt_profile(key, ciphertext):
    return parse_cookie(aes_ecb_decrypt(ciphertext, key, pad=True).decode())


@cryptopals.challenge(2, 13, 'ECB cut-and-paste')
def challenge13():
    length_for_full_padding = 32 - len('email=&uid=10&role=user')

    key = generate_random_aes_key()

    ciphertext = encrypted_profile(key, 'A' * length_for_full_padding)
    pad_block = ciphertext[32:]

    ciphertext = encrypted_profile(key, '666@gmail.com')
    email_block = ciphertext[:16]
    uid_role_block = ciphertext[16:32]

    ciphertext = encrypted_profile(key, ('A' * 10) + 'admin')
    admin_block = ciphertext[16:32]

    ciphertext = encrypted_profile(key, 'A' * 14)
    # this piece is necessary since the parsing routine split on '=' sign
    # and using the block obtained we remain with a '&rol' piece
    # so we create a block starting with an equal sign that will be decrypted
    # to garbage but who cares
    starting_with_equal_block = ciphertext[32:48]

    logger.info('ciphertext: \'%s\'' % ciphertext)

    plaintext = decrypt_profile(key, email_block + uid_role_block + admin_block + starting_with_equal_block + pad_block)

    logger.info('plaintext: \'%s\'' % plaintext)

    assert(plaintext['role'] == 'admin')


if __name__ == "__main__":
    from console import fg, fx, defx
    from console.screen import sc as screen
    from console.utils import wait_key, set_title, cls
    from console.constants import ESC

    exit_keys = (ESC, 'q', 'Q')

    cls()

    set_title('Cryptopals')
    with screen.location(4, 4):
        print(
            fg.lightgreen(f'** {fx.i}Cryptopals challenges! {defx.i}**'),
            screen.mv_x(5),  # back up, then down
            screen.down(40),
            fg.yellow(f'(Hit the {fx.reverse}ESC{defx.reverse} key to exit): '),
            end='', flush=True,
        )

    y = 10
    for sn, challenges in cryptopals.sets():
        y += 1
        with screen.location(2, y):
            print(fg.blue(f'Set {sn}'))
        y += 2
        for challenge in challenges:
            with screen.location(4, y):
                print(fg.blue(f'#{challenge.n} - {challenge.description}'))

            y += 1

    with screen.hidden_cursor():
        choice = wait_key()
        cls()
        cryptopals.exec(int(choice))
