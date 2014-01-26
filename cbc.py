'''Implementation of the CBC mode as described in the second
set of challenges.
'''
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
