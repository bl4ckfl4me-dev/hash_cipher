def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def key_schedule(key: bytes) -> list:
    key_bytes = list(key)

    round_keys = []
    for i in range(16):
        shifted_key = key_bytes[i % len(key_bytes):] + key_bytes[:i % len(key_bytes)]
        round_keys.append(bytes(shifted_key))

    return round_keys


def des_encrypt(block: bytes, key: bytes, m_i: bytes) -> bytes:
    if len(block) != 8 or len(key) != 8 or len(m_i) != 8:
        raise ValueError("Block, key, and m_i must all be 8 bytes.")

    left = block[:4]
    right = block[4:]
    round_keys = key_schedule(key)

    temp = xor_bytes(right, m_i)
    for round_key in round_keys:
        new_right = xor_bytes(temp, round_key)
        left, temp = temp, xor_bytes(left, new_right)

    return temp + left


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
