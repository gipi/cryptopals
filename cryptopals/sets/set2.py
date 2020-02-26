import logging
import base64

from ..meta import cryptopals
from ..utils import decodeBase64file, generate_random_bytes, generate_random_integer, _is_there_block_with_more_than_one_repetition
from ..cbc import aes_cbc_encrypt, aes_cbc_decrypt
from ..ecb import aes_ecb_encrypt, aes_ecb_decrypt
from ..paddings import pkcs7, depkcs7, PaddingException
from ..macro import generate_random_aes_key, xor
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


@cryptopals.challenge(2, 14, 'Byte-at-a-time ECB decryption (Harder)')
def challenge14():
    '''
    Now we have a different thing with respect to the #12: the oracle has the
    following form

        AES-128-ECB(random-prefix || attacker-controlled || secret-bytes, random-key)

    and we need to find "secret-bytes". Since "random-prefix" with each
    iteration changes also the length we need to be smart in order to break
    this cipher!

    The idea behind the procedure is that the "random-prefix" can only
    influence the ciphertext for the blocks in which is contained. For sure
    random-prefix has a maximum and minimum length possible and we can use our
    controlled string to increase the plaintext length up to causing a
    ciphertext with an increased number of blocks to appear.

    How this can help? if we find a certain attacker-controlled string that
    cause only one of the possible generated ciphertext to be one block more
    than the other this means that we have the last block composed uniquely
    with padding, and since equal plaintext corresponds to equal ciphertext we
    have something to play with!

    Using as the attacker-controlled string the plaintext of the padding block
    now we have an oracle for when our string is aligned to the block: our
    strategy is

     - start with the user-controlled string equal to the plaintext of the
       padding block
     - iterate each step filtering wrt the ciphertext of the padding block
     - add one byte to the right until you see a jump in the block size, call
       this value offset_0
     - use offset_0 - 15 and you'll have as last block

       [random prefix][user-controlled][secret-byte][s\\x1f *15]

    where "s" is the last byte of the secret-bytes.

'''
    secret_encoded_string = b'''
    Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
    aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
    dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
    YnkK'''
    secret_string = base64.b64decode(secret_encoded_string)
    logger.debug(f'secret_string length: {len(secret_string)}')
    r_min, r_max = 5, 35

    def _generate_random_prefix():
        r_length = generate_random_integer(r_min, r_max)
        return generate_random_bytes(r_length)

    key = generate_random_aes_key()
    block_size = 16  # FIXME: this must be calculated

    def _is_magic_length(_user_supplied, tries=300):
        jumped_blocks = []
        max_ = 0
        for _ in range(tries):
            _random_prefix = _generate_random_prefix()
            ciphertext = aes_ecb_encrypt(_random_prefix + _user_supplied + secret_string, key, pad=True)
            length = len(ciphertext) // block_size
            logger.debug(f'{len(_user_supplied):02d} {len(_random_prefix):02d} {len(secret_string):02d} -- {length:02d} {_random_prefix} {ciphertext[-16:-1]}')
            if length > max_:
                max_ = length
                jumped_blocks = [ciphertext[-16:]]
            elif length == max_:
                jumped_blocks.append(ciphertext[-16:])

        return len(set(jumped_blocks)) == 1, jumped_blocks[0]

    # we are logging for the final padding block of 16 bytes
    block_padding = None
    for count in range(0, 64):
        logger.debug(f'trying {count} bytes')
        is_magic, block_padding = _is_magic_length((b'A' * count))
        if is_magic:
            break

    # put a check in place just to check something isn't going banana
    if not is_magic:
        raise ValueError('failure to find the magic number')

    check_block_padding = aes_ecb_encrypt(b'\x10' * 0x10, key)  # FIXME: calculate block size

    print(f'find magic for {count}, obtained padding block equal to \'{block_padding.hex()}\'')

    if check_block_padding != block_padding:
        raise ValueError(f'obtained {block_padding.hex()} "\
            "but is different from {check_block_padding.hex()}')

    block_size = 0x10

    def _oracle(_user_text):
        # using a padding block we can recognize where starts our input
        # we use 'A' to be sure the random prefix doesn't interfere
        _poison_block = bytes([0x41] + [block_size] * block_size)
        _found = False
        while not _found:
            _random_prefix = _generate_random_prefix()
            _ciphertext = aes_ecb_encrypt(
                _random_prefix + _poison_block + _user_text + secret_string,
                key,
                pad=True)

            _offset = (_ciphertext[:-16]).find(block_padding)
            if _offset > -1:
                return _ciphertext[_offset + block_size:]

    b_length, c_length, offset = ecb_bruteforce_block_length(_oracle)
    print(f'block size: {b_length}')

    secret_length = c_length - b_length - offset
    print(f'secret has length of {secret_length}')

    recovered_secret = ecb_bruteforce(_oracle, b_length, secret_length)
    print(f'secret: {recovered_secret.decode()}')


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


def build_query(user_input):
    '''
        >>> build_query(b'miao')
        b'comment1=cooking%20MCs;userdata=miao;comment2=%20like%20a%20pound%20of%20bacon'
        >>> build_query(b'bau;')
        b'comment1=cooking%20MCs;userdata=bau;comment2=%20like%20a%20pound%20of%20bacon'
        >>> build_query(b'foo=kebab;')
        b'comment1=cooking%20MCs;userdata=fookebab;comment2=%20like%20a%20pound%20of%20bacon'

    '''
    def _quote(_input):
        return _input.replace(b'=', b'').replace(b';', b'')

    return b'comment1=cooking%20MCs;userdata=' \
        + _quote(user_input) \
        + b';comment2=%20like%20a%20pound%20of%20bacon'


@cryptopals.challenge(2, 16, 'CBC bitflipping attacks')
def challenge16():
    '''
    We need to break the cipher (CBC THIS TIME!) and to do that we need to know
    how the CBC decryption works: below a diagram for the decription of the
    ith + 1 block, as you can see it involves the ciphertext from the previous
    block

       Ci                      Ci+1
       |                       |
       |-----------.           |
    .-------.      |       .-------.
    |  AES  |      |       |  AES  |
    '-------'      |       '-------'
        |          |           |
        +          '-----------+
        |                      |
       \ /                    \ /
        '                      '
        Pi                     Pi+1

    This means that Pi+1 = Ci <+> Dec_k(Ci+1) but we know Pi+1 and Ci so we
    have Dec_k(Ci+1) and to obtain P'i+1 we can calculate P'i+1 <+> Pi+1 = H
    and xor it with Ci so to obtain

        Ci <+> H <+> Dec_k(Ci+1) = Pi+1 <+> H = P'i+1

    The tricky part is that we don't know precisely where our plaintext starts
    inside the final plaintext but that is only a guess (polynomial) work: we
    uses a user input large as a block and composed of the same characters, at
    that point we can "rotate" the xor until the offset is right ;)
    '''
    key = generate_random_aes_key()
    iv  = generate_random_aes_key()

    def _oracle_encrypt(_user_input):
        return aes_cbc_encrypt(build_query(_user_input), key, iv)

    def _oracle_decrypt(_ciphertext):
        return aes_cbc_decrypt(_ciphertext, key, iv)

    def _is_admin(_ciphertext):
        _plaintext = _oracle_decrypt(_ciphertext)
        logger.debug(_plaintext)

        return b';admin=true;' in _plaintext

    b_length, length, offset = ecb_bruteforce_block_length(_oracle_encrypt)

    logger.debug(f'block length: {b_length}')

    def _rotate(_text):
        return _text[1:] + _text[:1]

    # try to match up a block
    poison_msg = b'A' * b_length
    xored = xor(poison_msg, b';admin=true;')

    # get a "good" ciphertext to play with
    ciphertext = _oracle_encrypt(poison_msg)

    escalated = False
    for index in range((len(ciphertext) // b_length)):
        for offset in range(b_length):
            xored = _rotate(xored)
            poison_ciphertext = \
                ciphertext[b_length * index:b_length * (index + 1)] \
                + xor(
                    xored,
                    ciphertext[b_length * (index + 1):b_length * (index + 2)]) \
                + ciphertext[b_length * (index + 2):]

            if _is_admin(poison_ciphertext):
                escalated = True
                break

        if escalated:
            break

    if not escalated:
        raise ValueError('something went wrong :(')

    print(f'SUCCESS!! we escalated with a poisonous block \'{xored.hex()}\'')
