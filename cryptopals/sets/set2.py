import logging
import base64

from ..meta import cryptopals
from ..utils import decodeBase64file
from ..cbc import aes_cbc_encrypt, aes_cbc_decrypt
from ..ecb import aes_ecb_encrypt, aes_ecb_decrypt
from ..macro import generate_random_aes_key


logger = logging.getLogger(__name__)


@cryptopals.challenge(2, 10, 'Implement CBC mode')
def challenge10():
    ciphertext = decodeBase64file('challenge10.txt')

    key = b'YELLOW SUBMARINE'
    iv = b'\x00' * 16

    plaintext = aes_cbc_decrypt(ciphertext, key, iv)

    logger.info('AES-CBC-128: %s' % plaintext)


def encryption_oracle(plaintext):
    import random
    key = generate_random_aes_key()
    iv = generate_random_aes_key()

    ciphertext = None
    mode = None

    if random.getrandbits(1):
        mode = "CBC"
        ciphertext = aes_cbc_encrypt(plaintext, key, iv)
    else:
        mode = "ECB"
        ciphertext = aes_ecb_encrypt(plaintext, key, pad=True)

    return mode, ciphertext


@cryptopals.challenge(2, 11, 'An ECB/CBC detection oracle')
def challenge11():
    '''The point of this challenge is that if we control the plaintext
we can take apart ECB from CBC simply using repeated blocks; look at
the implemetation to find out how the magical "encryption oracle" works :P
'''
    plaintext = b'''0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'''

    mode, ciphertext = encryption_oracle(generate_random_bytes(5) + plaintext + generate_random_bytes(3))

    tipe = None
    if _is_there_block_with_more_than_one_repetition(ciphertext, 4):
        tipe = 'ECB'
    else:
        tipe = 'CBC'

    assert(mode == tipe)


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

    print('find out secret: ' + guessed.decode())


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
    '''Here something more pratical: we have a encoded profile data like

    {
      email: 'foo@bar.com',
      uid: 10,
      role: 'user'
    }

and we want to set 'role' to 'admin'.

In the threat model the user can change her email at will and obtain the resulting
ciphertext. Since it's encripted with ECB we can create custom blocks without problem
and reordering them to obtain "arbitrary" profiles!

  email=AAAAAAAAA& uid=10&role=user <padding       >   <--- here we get the padding
  email=666@gmail. com&uid=10&role= user<padding   >   <--- here we get the email and uid and the start of role
  email=AAAAAAAAAA admin&uid=10&rol e=user<padding >   <--- here we have the admin value (FIXME: probably we could set the padding directly here!)
  email=AAAAAAAAAA AAAA&uid=10&role =user<padding  >   <--- here we get a closing =user (with a padding of 11 bytes)
'''
    length_for_full_padding = 32 - len('email=&uid=10&role=user')

    # generate the key for the oracle
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

    print(f'plaintext: \'{plaintext}\'')

    assert(plaintext['role'] == 'admin')