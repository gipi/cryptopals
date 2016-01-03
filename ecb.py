'''Implementation of the ECB mode using AES as cipher primitive
'''
from Crypto.Cipher import AES
from macro import (
    pkcs7,
    depkcs7,
)


def aes_ecb_encrypt(plaintext, key, pad=False):
    aes = AES.new(key, AES.MODE_ECB)

    if pad:
        plaintext = pkcs7(plaintext, len(key))

    return aes.encrypt(plaintext)


def aes_ecb_decrypt(ciphertext, key, pad=False):
    aes = AES.new(key, AES.MODE_ECB)
    plaintext = aes.decrypt(ciphertext)

    if pad:
        plaintext = depkcs7(plaintext)

    return plaintext
