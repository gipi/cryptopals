import logging
from typing import Callable
from .paddings import depkcs7


logger = logging.getLogger(__name__)


def get_block(c, n, block_length):
    return c[n * block_length:(n + 1) * block_length]


def ecb_bruteforce_block_length(oracle, limit=64):
    '''Tries to obtain the block length finding when the ciphertext
    jumps.

    Args:
        oracle: the actual function that produces ciphertext, must take the
                user supplied string as first argument
        limit: the upper limit for the search space

    Returns:
        block_length, length, count : a tuple with the obtained block_length
                     the length of the ciphertext with a final block composed
                     only by padding and the length of the user controlled
                     string to obtain such configuration.
    '''
    block_length = None
    length = None

    # first we get the length with empty user input
    ciphertext = oracle(b'')
    length_start = len(ciphertext)

    for count in range(limit):
        payload = b'A' * count

        ciphertext = oracle(payload)
        length = len(ciphertext)
        if length > length_start:
            block_length = length - length_start
            break

    if not block_length:
        raise ValueError('failed to find the block length')

    return block_length, length, count


def ecb_bruteforce(oracle, block_length, secret_length):
    '''Implementation of the ECB bruteforce.

    Args:
        oracle: the actual function that produces ciphertext, must take the
                user supplied string as first argument
        block_length: the length of the block for this cipher
        secret_length: the supposed length of the secret to be extracted
    '''
    guessed = b''
    step = 0

    while len(guessed) < secret_length:
        block_number = len(guessed) // block_length
        logger.debug(f'step: {step} block: {block_number}')
        prefix = b'A' * ((block_length - (step + 1)) % block_length)

        ciphertext = oracle(prefix)

        poisoned_block = get_block(ciphertext, block_number, block_length)
        logger.debug(f'poisoned block: {poisoned_block.hex()}')

        found = False
        for c in range(256):  # first block
            if step < block_length:
                real_prefix = prefix + guessed
            else:  # remaining blocks
                base = (step + 1) - block_length
                end = base + (block_length - 1)
                real_prefix = guessed[base:end]

            guess = oracle(real_prefix + bytes([c]))[:block_length]
            logger.debug(f'guessed block: {guess.hex()}')

            if guess == poisoned_block:
                guessed = guessed + bytes([c])
                step += 1
                found = True
                break

        if not found:
            raise ValueError(f'bruteforcing failed! recovered {len(guessed)} bytes guessed: \'{guessed.decode()}\'')

    return guessed


def xored_padding(count, block_length):
    original = bytes((block_length - count) * [0x00] + count * [count])
    next = bytes((block_length - count) * [0x00] + count * [count + 1])

    return bytes([_a ^ _b for _a, _b in zip(original, next)])


from typing import Protocol


class OracleProtocol(Protocol):
    def check_padding(self, ciphertext: bytes) -> bool:
        pass


def cbc_bruteforce_padding_single_block(block0, block1,
                                        block_size: int,
                                        oracle: OracleProtocol):
    """Bruteforce a CBC block using a padding oracle"""
    plaintext_block = []
    idx_inside_block = block_size - 1

    while idx_inside_block > -1:
        padding_value = block_size - idx_inside_block
        logger.debug(f'''{idx_inside_block=} {padding_value=}''')
        # try 0 as last resort to avoid having a false positive
        for b in list(range(1, 256)) + [0]:
            block0_modified = block0[:idx_inside_block] + \
                bytes([b ^ block0[idx_inside_block]]) + \
                block0[idx_inside_block + 1:]
            # 
            c = block0_modified + block1
            if oracle.check_padding(c):
                break

        original = b ^ padding_value

        plaintext_block.append(bytes([original]))

        logger.debug(f'{b=:x} "{chr(original)}" ({hex(original)})')

        idx_inside_block -= 1
        xor_mask = xored_padding(padding_value, block_size)
        block0 = bytes([a ^ b for a, b in zip(xor_mask, block0_modified)])

    return plaintext_block[::-1]


def cbc_bruteforce_padding(iv, ciphertext, block_size, 
                           oracle: OracleProtocol):
    """Bruteforces the (iv, ciphertext) using a padding oracle"""
    # we use the iv as the starting block
    blocks = iv + ciphertext

    n_blocks = len(blocks) // block_size

    resolved_block = 0

    plaintext_bytes = []

    # we need to resolve all but the first block (that is the iv)
    while resolved_block < (n_blocks - 1):
        logger.debug(f'''resolved block: {resolved_block}''')

        block0 = get_block(blocks, resolved_block, block_size)
        block1 = get_block(blocks, resolved_block + 1, block_size)

        plaintext_block = cbc_bruteforce_padding_single_block(
            block0,
            block1,
            block_size,
            oracle)

        # remember that the byte are revealed in reverse
        plaintext_bytes.extend(plaintext_block)
        logger.debug(f'original plaintext: {b"".join(plaintext_bytes).decode("utf-8")}')

        resolved_block += 1

    return depkcs7(b"".join(plaintext_bytes))
