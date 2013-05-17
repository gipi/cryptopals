```python
i = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
In [92]: binascii.a2b_hex(bytearray(i))
Out[92]: "I'm killing your brain like a poisonous mushroom"
In [93]: base64.b64encode(binascii.a2b_hex(bytearray(i)))
Out[93]: 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
[x^y for x in bytearray(binascii.a2b_hex(a)) for y in bytearray(binascii.a2b_hex(b))]
```