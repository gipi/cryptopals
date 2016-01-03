'''Implementation of the CBC mode as described in the second
set of challenges.
'''
from macro import (
    xor,
    chunks,
    pkcs7,
	depkcs7,
)
from ecb import aes_ecb_encrypt, aes_ecb_decrypt
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


def cbc_decrypt(ciphertext, key, iv, cipher_func):
    '''Implementation of the CBC mode to decrypt.

    We suppose that the ciphertext is padded.
    '''
    if len(iv) != len(key):
        raise ValueError('IV and the key must have the same size')

    logger.debug('cbc initializated with key: \'%s\' and iv: \'%s\'' % (
        key, iv,
    ))

    block_size = len(key)

    plaintext = b''

    for c_i in chunks(ciphertext, block_size):
        logger.debug('c_i: %s c_i-1: %s' % (
            c_i, iv,
        ))

        plainblock = cipher_func(c_i, key)

        m_i = xor(plainblock, iv)
        logger.debug('m_i: %s' % m_i)
        plaintext += m_i

        iv = c_i

    #plaintext_padded = pkcs7(plaintext, block_size)

    return depkcs7(plaintext)

def cbc(plaintext, key, iv, cipher_func):
    '''Implementation of the CBC mode'''
    if len(iv) != len(key):
        raise ValueError('IV and the key must have the same size')

    block_size = len(key)

    plaintext_padded = pkcs7(plaintext, block_size)

    ciphertext = b''

    for chunk in chunks(plaintext_padded, block_size):
        xored = xor(chunk, iv)
        cipherblock = cipher_func(xored, key)
        ciphertext += cipherblock

        iv = cipherblock

    return ciphertext

def aes_cbc_encrypt(plaintext, key, iv):
    return cbc(plaintext, key, iv, aes_ecb_encrypt)

def aes_cbc_decrypt(plaintext, key, iv):
    return cbc_decrypt(plaintext, key, iv, aes_ecb_decrypt)
