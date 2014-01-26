'''Implementation of the CBC mode as described in the second
set of challenges.
'''
from macro import (
    xor,
    chunks,
)
from ecb import aes_ecb_encrypt, aes_ecb_decrypt
import logging

logger = logging.getLogger(__name__)


def pkcs7(message, block_size):
    '''
    Described in
    
        http://tools.ietf.org/html/rfc5652#section-6.3

    Usage:

        >>> pkcs7(b'\\x01\\x02\\x03\\x04', 4)
        b'\\x01\\x02\\x03\\x04\\x04\\x04\\x04\\x04'
        >>> pkcs7(b'\\x01\\x02\\x03\\x04\\x05', 4)
        b'\\x01\\x02\\x03\\x04\\x05\\x03\\x03\\x03'
        >>> pkcs7(b'\\x01\\x02\\x03', 4)
        b'\\x01\\x02\\x03\\x01'
    '''
    # calculate how much bytes remain to full the size
    len_message = len(message)
    pad = block_size - (len_message % block_size)

    logger.debug('pkcs7: #=%d with pad: %d' % (len_message, pad))

    padding = bytes([pad,])*pad

    return message + padding

def depkcs7(message):
    '''Reverse the operation of pkcs7.

        >>> depkcs7(b'\\x00\\x00\\x00\\x00\\x04\\x04\\x04\\x04')
        b'\\x00\\x00\\x00\\x00'
        >>> depkcs7(b'\\x00\\x00\\x00\\x00\\x04\\x04\\x04')
        Traceback (most recent call last):
            ...
        Exception: Padding wrong
    '''
    pad = int(message[-1])

    #import ipdb;ipdb.set_trace()

    # check that the padding make sense
    for i in range(1, pad + 1):
        if message[-i] != pad:
            raise Exception('Padding wrong')# TODO: make custom exception

    return message[:-pad]

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


    return depkcs7(plaintext)

def aes_cbc_decrypt(plaintext, key, iv):
    return cbc_decrypt(plaintext, key, iv, aes_ecb_decrypt)
