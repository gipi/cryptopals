'''Implementation of the ECB mode using AES as cipher primitive
'''
from Crypto.Cipher import AES

def aes_ecb_encrypt(plaintext, key):
    aes = AES.new(key, AES.MODE_ECB)
    return aes.encrypt(plaintext)

def aes_ecb_decrypt(plaintext, key):
    aes = AES.new(key, AES.MODE_ECB)
    return aes.decrypt(plaintext)
