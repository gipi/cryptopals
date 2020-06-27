"""
CTR, the stream cipher mode
"""
from Crypto.Cipher import AES
import struct

from .macro import xor


class CTR(object):
    """
    An instance of this class is capable of generating "infinite amount" of
    keystream.

        >>> ctr = CTR(b'kebab', b'falafel')
        >>> next(ctr)
    """
    def __init__(self, key: bytes, nonce: bytes):
        self.count = 0
        self.key = key
        self.nonce = nonce
        self.aes = AES.new(key, AES.MODE_ECB)

    def _get_running_counter(self) -> bytes:
        return struct.pack("pQ", self.nonce, self.count)

    def __next__(self) -> bytes:
        stream = self.aes.encrypt(self._get_running_counter())

        self.count += 1

        return stream


def _ctr(key: bytes, nonce: bytes, data: bytes) -> bytes:
    length = len(data)

    ctr = CTR(key, nonce)

    count = (len(data) // 16) + 1

    stream = b''
    for _ in range(count):
        stream += next(ctr)

    # FIXME: we need to store somewhere the remaining stream bytes
    stream = stream[:length]

    return xor(data, stream)


"""
ATTENTION: these functions make sense called in a session otherwise won't happen
what you expect!
"""


def ctr_encrypt(key: bytes, nonce: bytes, plaintext: bytes) -> bytes:
    """CTR encrypt message"""
    return _ctr(key, nonce, plaintext)


def ctr_decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """CTR decrypt message"""
    return _ctr(key, nonce, ciphertext)

