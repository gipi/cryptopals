import logging


logger = logging.getLogger(__name__)


class PaddingException(Exception):
    pass


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
        >>> pkcs7(b'YELLOW SUBMARINE', 20)
        b'YELLOW SUBMARINE\\x04\\x04\\x04\\x04'
    '''
    # calculate how much bytes remain to full the size
    len_message = len(message)
    pad = block_size - (len_message % block_size)

    logger.debug('pkcs7: #=%d with pad: %d' % (len_message, pad))

    padding = bytes([pad, ]) * pad

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

    # check that the padding makes sense
    for i in range(1, pad + 1):
        if message[-i] != pad:
            raise PaddingException('wrong padding')  # TODO: make custom exception

    return message[:-pad]


