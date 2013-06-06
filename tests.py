import unittest

from macro import encode, decode, xor, hamming_distance

class CodeTests(unittest.TestCase):
    def test_encode(self):
        self.assertEqual(encode('\x41'), '41')

    def test_decode(self):
        self.assertEqual(decode('41'), '\x41')

    def test_xor(self):
        self.assertEqual(xor("00", "00"), "00")
        self.assertEqual(xor("FF", "00"), "ff")
        self.assertEqual(xor("00", "FF"), "ff")
        self.assertEqual(xor("FF", "FF"), "00")

    def test_xor_unmatching(self):
        """Check that if we pass a key with length different
        that source all is right"""
        self.assertEqual(
            xor('00FF00', 'ff'),
            'ff00ff'
        )

    def test_hamming(self):
        self.assertEqual(
            hamming_distance('A', 'B'),
            2
        )
        self.assertEqual(
            hamming_distance('B', 'A'),
            2
        )
        self.assertEqual(
            hamming_distance('AA', 'AB'),
            2
        )
        self.assertEqual(
            hamming_distance(
                'this is a test',
                'wokka wokka!!!'
                ),
            37
        )
