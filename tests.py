import unittest
import os

from macro import (
    encode,
    decode,
    xor,
    hamming_distance,
    is_ascii,
    how_much_is_actually_english,
    transpose,
    decodeBase64file,
    chunks,
    find_multiple_occurences_positions,
    find_multiple_occurences,
    find_frequencies,
    matrixify,
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
        self.assertTrue(is_ascii(b'#'))
        #self.assertFalse(is_ascii(b'\t'))

    def test_how_much_is_english(self):
        from macro import ENGLISH_FREQUENCIES

        single_char = b'a'
        score_single_char = how_much_is_actually_english(single_char)
        expected_score_single_char = 1 - ENGLISH_FREQUENCIES['a']/100

        self.assertTrue(score_single_char == expected_score_single_char, 'We expect %f, not %f' % (expected_score_single_char, score_single_char))
        simple_phrase = b'this is a simple phrase'
        simple_sequence = b'!a.0&% 7x!|*#,;$\%()?^'

        score_simple_phrase = how_much_is_actually_english(simple_phrase)
        self.assertTrue(score_simple_phrase > 0)

        score_simple_sequence = how_much_is_actually_english(simple_sequence)
        self.assertTrue(score_simple_sequence > 0)

        simple_phrase_with_weird_chars = b'this\x00is\x00a\x00simple\x00phrase'
        #self.assertTrue(
        #    how_much_is_actually_english(simple_phrase) < how_much_is_actually_english(simple_phrase_with_weird_chars)
        #)

        self.assertTrue(score_simple_phrase < score_simple_sequence, '%f not lower than %f' % (score_simple_phrase, score_simple_sequence,))

        simple_sequence_gibberish = b'dyeueudheijidjdijdijdie'

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

    def test_matrixify(self):
        data = b'\x00\x01\x02\x03AB'
        matrix = list(matrixify(data, 2))

        print('%s' % matrix)

        self.assertEqual(matrix[0], b'\x00\x01')
        self.assertTrue(matrix[1] == b'\x02\x03')
        self.assertEqual(matrix[2], b'AB')

    def test_transpose(self):
        text = b"0123456789"
        matrix = list(matrixify(text, 5))

        self.assertEqual(matrix[0], b'01234')
        self.assertEqual(matrix[1], b'56789')

        it = transpose(matrix)

        self.assertEqual(it[0], b"05")
        self.assertEqual(it[1], b"16")
        self.assertEqual(it[2], b"27")
        self.assertEqual(it[3], b"38")
        self.assertEqual(it[4], b"49")

        # transpose is idempotent
        print('%s' % list(transpose(it)))

    def test_base64(self):
        import tempfile
        import base64

        plaintext = b'this is a base64 encoded text'
        encodedtext = ''

        with tempfile.NamedTemporaryFile(delete=False) as fp:
            fp.write(base64.b64encode(plaintext))
            fp.flush()
            encodedtext = decodeBase64file(fp.name)

        self.assertEqual(plaintext, encodedtext)

        os.unlink(fp.name)

    def test_occurences(self):
        msg = 'aaaabbbbccccaaaa'
        chunkz = list(chunks(msg, 4))
        self.assertEqual(len(chunkz), 4)

        result = find_multiple_occurences_positions(msg, 4)
        self.assertEqual(len(result), 3)
        self.assertEqual(len(result['aaaa']), 2)
        self.assertEqual(len(result['bbbb']), 1)

        result = find_multiple_occurences(msg, 4)
        self.assertEqual(len(result), 3)
        self.assertEqual(result['aaaa'], 2)

    def test_frequencies(self):
        msg = 'a'*5
        freq = find_frequencies(msg)

        self.assertEqual(freq['a'], 1.0)

        msg = ('a'*5) + ('b'*10)
        freq = find_frequencies(msg)

        self.assertEqual(freq['a'], 0.3333333333333333)
        self.assertEqual(freq['b'], 0.6666666666666666)

        msg = 'abc'
        freq = find_frequencies(msg, 2)

        self.assertEqual(freq['ab'], 0.3333333333333333)
        self.assertEqual(freq['bc'], 0.3333333333333333)
