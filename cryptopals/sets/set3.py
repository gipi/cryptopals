"""
These are the solutions for the set at <https://cryptopals.com/sets/3>.
"""
import logging
import random
import base64
from ..meta import cryptopals
from ..macro import generate_random_aes_key, generate_random_aes_IV
from ..cbc import aes_cbc_encrypt, aes_cbc_decrypt
from ..paddings import PaddingException
from ..oracle import get_block, cbc_bruteforce_padding
from ..ctr import ctr_decrypt


logger = logging.getLogger(__name__)


@cryptopals.challenge(3, 17, "The CBC padding oracle")
def challenge17():
    """
    Here we are: we have a oracle that provides us with a ciphertext and
    the possibility to know if the padding is wrong! if we analyze the way
    CBC decryption works, we see that we can control the ciphertext, either
    as a content either the block ordering :)

    This is the diagram

       Ci                     Ci+1
        |                      |
        |----------.           |---------
    .-------.      |       .-------.
    |  AES  |      |       |  AES  |
    '-------'      |       '-------'
        |          |           |
 ------(+)         '----------(+)
        |                      |
       \ /                    \ /
        '                      '
        Pi                     Pi+1

    If we xor Ci with one byte at its end we have

        C'i (+) DEC(Ci+1) = Ci (+) b (+) DEC(Ci+1) 
                          = b (+) Ci (+) DEC(Ci+1) 
                          = <unknown plaintext> (+) b
                          = <unknown plaintext[:-1]> | 0x01

    i.e

        b (+) p = 0x01 ----> p = b (+) 0x01

    The idea is to use two blocks at the time, the first as the xoring
    block against the second block, modifying the last byte in order to
    leak when a correct padding is generated; (probably) when a correct
    padding is triggered we have a 01 padding: this allows to deduce the
    hidden value in the plaintext for that byte!

     ,---------------.
     |   block0      |
     '---------------'
            (+)
     ,---------------.
     |   block1 | 01 |
     '---------------'

    At this point we can recursively move our attention to the next byte (to
    the left) we can modify the last byte of the known-plaintext to be 02 so
    to try to hit the correct padding value of 02 in the next guessing.

    This procedure can continue for all the block without problem, the only
    thing to take into consideration is that is possible to encounter a block
    where a padding is already present, so special care must follow.

    When a block is completed you can pass safely to the next block shifting of
    one place to the right the role of block0 and block1 (block0 being the block
    just deciphered, but this fact is not important).

    Take in mind that in CBC the first block is the IV.
    """
    plaintexts = [
        "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
        "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1"
        "bXBpbic=",
        "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
        "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
        "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
        "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
        "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
        "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
        "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
        "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
    ]

    class Oracle(object):

        def __init__(self):
            self.key = generate_random_aes_key()
            self.iv = generate_random_aes_IV()

        def __next__(self):
            self.plaintext = base64.b64decode(random.choice(plaintexts))

            logger.debug(f'oracle has chosen the plaintext: "{self.plaintext.decode("utf-8")}"')

            ciphertext = aes_cbc_encrypt(
                self.plaintext,
                self.key,
                self.iv
            )

            return self.iv, ciphertext

        @property
        def block_size(self):
            return 16

        def check_padding(self, ciphertext):
            is_padding_good = None

            try:
                aes_cbc_decrypt(ciphertext, self.key, self.iv)
                is_padding_good = True
            except PaddingException:
                is_padding_good = False

            return is_padding_good

    game = Oracle()

    iv, ciphertext = next(game)

    plaintext = cbc_bruteforce_padding(iv, ciphertext, game.block_size, game)

    print(plaintext.decode('utf-8'))

    assert game.plaintext == plaintext, f"{plaintext=} != {game.plaintext=}"


@cryptopals.challenge(3, 18, "Implement CTR, the stream cipher mode")
def challenge18() -> None:
    """
    We are going to explore the CTR mode, it transform a block cipher in a
    stream cipher with very little effort :)
    """
    ciphertext = base64.b64decode("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/"
                                  "2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")

    plaintext = ctr_decrypt(b"YELLOW SUBMARINE", b'\x00', ciphertext)

    print(plaintext)
