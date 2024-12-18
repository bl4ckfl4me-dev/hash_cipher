def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def key_schedule(key: bytes) -> list:
    key_bytes = list(key)

    round_keys = []
    for i in range(16):
        shifted_key = key_bytes[i % len(key_bytes):] + key_bytes[:i % len(key_bytes)]
        round_keys.append(bytes(shifted_key))

    return round_keys


def des_encrypt(block: bytes, key: bytes) -> bytes:
    if len(block) != 8 or len(key) != 8:
        raise ValueError("Block and key must both be 8 bytes.")

    left = block[:4]
    right = block[4:]
    round_keys = key_schedule(key)

    for round_key in round_keys:
        new_right = xor_bytes(right, round_key)
        left, right = right, xor_bytes(left, new_right)

    return right + left


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
        h_i = des_encrypt(temp, key)    # E(M(i) ⊕ H(i - 1))(M(i))
        h_i = xor_bytes(h_i, m_i)       # ⊕ M(i)
        h_prev = h_i                    # обновляем H(i - 1)
        result_hash += h_i              # добавляем H(i) к результату

    return result_hash[:block_size]
