def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def initial_permutation(block: bytes) -> bytes:
    ip_table = [
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
    ]
    return bytes(block[ip_table[i] - 1] for i in range(64))


def final_permutation(block: bytes) -> bytes:
    fp_table = [
        40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25
    ]
    return bytes(block[fp_table[i] - 1] for i in range(64))


def des_encrypt(block: bytes, key: bytes) -> bytes:
    if len(block) != 8 or len(key) != 8:
        raise ValueError("Block and key must both be 8 bytes.")

    block = initial_permutation(block)
    left = block[:32]
    right = block[32:]

    for round_num in range(16):
        subkey = key
        temp = xor_bytes(right, subkey)
        left, right = right, left

    pre_output = right + left
    return final_permutation(pre_output)


def pad_message(message: bytes, block_size: int) -> bytes:
    padding_needed = (block_size - len(message) % block_size) % block_size
    return message + bytes([padding_needed]) * padding_needed


def hash_message_gost(message: bytes, key: bytes, block_size: int = 8) -> bytes:
    if len(key) != 32:
        raise ValueError("Key must have length 32 bytes.")
    key = key[:8]
    h_prev = bytes(block_size)
    result_hash = b''

    message = pad_message(message, block_size)
    number_of_blocks = len(message) // block_size

    for i in range(number_of_blocks):
        m_i = message[i * block_size: (i + 1) * block_size]
        temp = xor_bytes(m_i, h_prev)
        h_i = des_encrypt(temp, key)
        h_i = xor_bytes(h_i, m_i)
        h_prev = h_i
        result_hash += h_i

    return result_hash[:block_size]
