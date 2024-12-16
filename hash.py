def pad(data: bytes) -> bytes:
    padding_len = 8 - (len(data) % 8)
    return data + bytes([padding_len] * padding_len)


def hash_message_gost(message: bytes, key: bytes, block_size: int = 8) -> bytes:
    message = pad(message)
    blocks = [message[i:i + block_size] for i in range(0, len(message), block_size)]
    h_prev = bytes([0] * block_size)
    for block in blocks:
        encrypted = gost_encrypt_block(h_prev, key)
        intermediate = int.from_bytes(encrypted, 'little') ^ int.from_bytes(block, 'little')
        h_prev = intermediate.to_bytes(block_size, 'little')
    return h_prev


def gost_encrypt_block(block: bytes, key: bytes) -> bytes:
    left = int.from_bytes(block[:4], byteorder='little')
    right = int.from_bytes(block[4:], byteorder='little')
    key_parts = [int.from_bytes(key[i:i + 4], byteorder='little') for i in range(0, 32, 4)]
    for i in range(24):
        right, left = gost_round(left, right, key_parts[i % 8])
    for i in range(8):
        right, left = gost_round(left, right, key_parts[7 - i])
    return left.to_bytes(4, byteorder='little') + right.to_bytes(4, byteorder='little')


def gost_round(left: int, right: int, key: int) -> (int, int):
    temp = (left + key) % (2 ** 32)
    shift = 11

    temp = ((temp << shift) & 0xFFFFFFFF) | (temp >> (32 - shift))
    new_right = right ^ temp

    return new_right, left
