import unittest

from macro import (
    encode,
    decode,
    xor,
    hamming_distance,
    is_ascii,
    transpose,
)

class CodeTests(unittest.TestCase):
    def test_encode(self):
        self.assertEqual(encode(b'\x41'), b'41')
        self.assertEqual(encode(b'ABCD'), b'41424344')

    def test_decode(self):
        self.assertEqual(decode(b'41'), b'\x41')
        self.assertEqual(decode(b'41424344'), b'\x41\x42\x43\x44')

    def test_xor(self):
        self.assertEqual(xor(b"\x00", b"\x00"), b"\x00")
        self.assertEqual(xor(b"\xFF", b"\x00"), b"\xff")
        self.assertEqual(xor(b"\x00", b"\xff"), b"\xff")
        self.assertEqual(xor(b"\xFF", b"\xFF"), b"\x00")

    def test_xor_unmatching(self):
        """Check that if we pass a key with length different
        that source all is right"""
        self.assertEqual(
            xor(b'\x00\xFF\x00', b'\xff'),
            b'\xff\x00\xff'
        )

    def test_ascii(self):
        self.assertTrue(is_ascii(b'I need to rest'))
        self.assertTrue(is_ascii(b'''I need to rest
        '''))
        self.assertFalse(is_ascii(b'#'))
        self.assertFalse(is_ascii(b'\t'))

    def test_hamming(self):
        self.assertEqual(
            hamming_distance(b'A', b'B'),
            2
        )
        self.assertEqual(
            hamming_distance(b'B', b'A'),
            2
        )
        self.assertEqual(
            hamming_distance(b'AA', b'AB'),
            2
        )
        self.assertEqual(
            hamming_distance(
                b'this is a test',
                b'wokka wokka!!!'
                ),
            37
        )

    def test_transpose(self):
        text = b"0123456789"
        it = transpose(text, 10)
        self.assertEqual(next(it), b"0")
        self.assertEqual(next(it), b"1")

        it = transpose(text, 5)
        self.assertEqual(next(it), b"05")
        self.assertEqual(next(it), b"16")
