matrix = (
    (4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3),
    (14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9),
    (5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11),
    (7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3),
    (6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2),
    (4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14),
    (13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12),
    (1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12),
)


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def key_schedule(key: bytes) -> list:
    key_bytes = list(key)

    round_keys = []
    for i in range(16):
        shifted_key = key_bytes[i % len(key_bytes):] + key_bytes[:i % len(key_bytes)]
        round_keys.append(bytes(shifted_key))

    return round_keys


def get_out(inright: int, key: bytes):
    out = 0
    temp = (inright + int(key)) % (1 << 32)
    for i in range(8):
        phonetic = (temp >> (4 * i)) & 0b1111
        out |= (matrix[i][phonetic] << (4 * i))
    out = ((out >> 21) | (out << 11)) & 0xFFFFFFFF
    return out


def crypt_operation(inleft, inright, key):
    outleft = inright
    outright = inleft ^ get_out(inright, key)
    return outleft, outright


def gost_encrypt(text:bytes, key):
    text = int(text.hex(), 16)
    text_left = text >> 32
    text_right = text & 0xFFFFFFFF
    for q in range(24):
        text_left, text_right = crypt_operation(text_left, text_right, key[q % 8])
    for q in range(8):
        text_left, text_right = crypt_operation(text_left, text_right, key[7 - q])
    hash = (text_left << 32) | text_right
    return hash


def des_encrypt(block: bytes, key: bytes, m_i: bytes) -> bytes:
    if len(block) != 8 or len(key) != 8 or len(m_i) != 8:
        raise ValueError("Block, key, and m_i must all be 8 bytes.")

    temp = xor_bytes(block[4:], m_i)
    key_schedule_gost = key_schedule(key)
    encrypted = gost_encrypt(temp, key_schedule_gost)

    return encrypted[:4] + block[:4]


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
        temp = xor_bytes(m_i, h_prev)   # M(i) ⊕ H(i - 1)
        h_i = des_encrypt(temp, key, m_i)    # E(M(i) ⊕ H(i - 1))(M(i))
        h_i = xor_bytes(h_i, m_i)       # ⊕ M(i)
        h_prev = h_i                    # обновляем H(i - 1)
        result_hash += h_i              # добавляем H(i) к результату

    return result_hash[:block_size]
