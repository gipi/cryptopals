# return an byte iterable from an hexadecimal representation
decode = lambda x:bytearray(binascii.a2b_hex(x))

# return a representation of two binary hexadecimal representation
xor = lambda x,y:"".join(['%02x' % (x^y,) for (x,y) in zip(decode(x), decode(y))])