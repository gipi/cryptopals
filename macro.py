# return an byte iterable from an hexadecimal representation
decode = lambda x:bytearray(binascii.a2b_hex(x))