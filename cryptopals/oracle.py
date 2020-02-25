import logging


logger = logging.getLogger(__name__)


def get_block(c, n, block_length):
    return c[n * block_length:(n + 1) * block_length]


def ecb_bruteforce_block_length(oracle, limit=64):
    '''Tries to obtain the block length finding when the ciphertext
    jumps.

    Args:
        oracle: the actual function that produces ciphertext, must take the
                user supplied string as first argument
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
