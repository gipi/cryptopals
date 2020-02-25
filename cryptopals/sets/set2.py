import logging
import base64

from ..meta import cryptopals
from ..utils import decodeBase64file, generate_random_bytes, _is_there_block_with_more_than_one_repetition
from ..cbc import aes_cbc_encrypt, aes_cbc_decrypt
from ..ecb import aes_ecb_encrypt, aes_ecb_decrypt
from ..paddings import pkcs7, depkcs7, PaddingException
from ..macro import generate_random_aes_key
from ..oracle import ecb_bruteforce, ecb_bruteforce_block_length


logger = logging.getLogger(__name__)


@cryptopals.challenge(2, 9, 'Implement PKCS#7 padding')
def challenge9():
    '''We are implementing basic PKCS#7 padding: if in a block are missing N
    bytes we pad with the number of bytes themself: for example if the block
    size is 20 bytes then the padded version for "YELLOW SUBMARINE" will be

    "YELLOW SUBMARINE\\x04\\x04\\x04\\x04"
'''
    plaintex = b'YELLOW SUBMARINE'
    plaintex_w_padding = b'YELLOW SUBMARINE\x04\x04\x04\x04'
    assert pkcs7(plaintex, 20) == plaintex_w_padding


@cryptopals.challenge(2, 10, 'Implement CBC mode')
def challenge10():
    ciphertext = decodeBase64file('challenge10.txt')

    key = b'YELLOW SUBMARINE'
    iv = b'\x00' * 16

    plaintext = aes_cbc_decrypt(ciphertext, key, iv)

    print(f'plaintext: \'{plaintext.decode()}\'')


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
    '''
    Here we are trying to decrypt the "unknown-string" in the following
    construction

        AES-128-ECB(your-string || unknown-string, random-key)

    This is possible using the following recipe:

     1. find out the block size (increase length of your-string until the
        ciphertext jumps of size)
     2. set your-string as a padding of length block_size - 1 and save the
        resulting ciphertext block
     3. loop over all the possible blocks with your-string set to the padding
        of the previous step plus a variable last byte. One of the resulting
        ciphertext is equal to the one found in the previous step, telling us
        the unknown-string's first byte.
     4. repeat step 3 and 4 using the recovered bytes in order to reduce the
        padding length until you recover all the bytes.
    '''
    secret_encoded_string = '''
    Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
    aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
    dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
    YnkK'''

    secret_string = base64.b64decode(secret_encoded_string)

    key = generate_random_aes_key()

    # this is the oracle that returns to us the ciphertext
    def _oracle(_user_supplied_string):
        logger.debug(f'input: {_user_supplied_string.hex()}')
        return aes_ecb_encrypt(
            _user_supplied_string + secret_string,
            key,
            pad=True)

    block_length, ciphertext_length, offset = \
        ecb_bruteforce_block_length(_oracle)

    secret_length = ciphertext_length - block_length - offset

    print(f'found block length equal to {block_length}')
    print(f'found secret length equal to {secret_length}')

    guessed = ecb_bruteforce(_oracle, block_length, secret_length)

    print(f'unknown-string: \'{guessed.decode()}\'')


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
    return aes_ecb_encrypt(
        bytes(encode_cookie(profile_for(email)), 'utf-8'),
        key,
        pad=True)


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

    In the threat model the user can change her email at will and obtain the
    resulting ciphertext. Since it's encripted with ECB we can create custom
    blocks without problem and reordering them to obtain "arbitrary" profiles!

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


@cryptopals.challenge(2, 15, 'PKCS#7 padding validation')
def challenge15():
    '''Now we need to have a routine that validates a padded string via PKCS#7: for example

    "ICE ICE BABY\\x04\\x04\\x04\\x04"

is correctly padded, instead

    "ICE ICE BABY\\x05\\x05\\x05\\x05"

or

    "ICE ICE BABY\\x01\\x02\\x03\\x04"

should raise an exception.
'''
    correct = b'ICE ICE BABY\x04\x04\x04\x04'
    wrongs = [
        b'ICE ICE BABY\x05\x05\x05\x05',
        b'ICE ICE BABY\x01\x02\x03\x04'
    ]

    assert depkcs7(correct) == b'ICE ICE BABY'

    for wrong in wrongs:
        raised = False
        try:
            depkcs7(wrong)
        except PaddingException:
            raised = True

        assert raised
