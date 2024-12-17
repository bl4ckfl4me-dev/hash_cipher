def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def des_encrypt(block: bytes) -> bytes:
    return block[::-1]


def pad_message(message: bytes, block_size: int) -> bytes:
    padding_needed = (block_size - len(message) % block_size) % block_size
    return message + bytes([padding_needed]) * padding_needed


def hash_message_gost(message: bytes, key: bytes, block_size: int = 8) -> bytes:
    # Проверка длины ключа
    if len(key) != 32:
        raise ValueError("Ключ должен иметь длину 32 байта.")

    key = key[:8]
    h_prev = bytes(block_size)
    result_hash = b''

    message = pad_message(message, block_size)
    number_of_blocks = len(message) // block_size

    for i in range(number_of_blocks):
        m_i = message[i * block_size: (i + 1) * block_size]

        # H(i) = E(M(i) ⊕ H(i-1))(M(i)) ⊕ M(i)
        temp = xor_bytes(m_i, h_prev)
        h_i = des_encrypt(temp)
        h_i = xor_bytes(h_i, m_i)

        h_prev = h_i
        result_hash += h_i

    return result_hash[:block_size]
