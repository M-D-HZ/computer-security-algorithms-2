import hashlib

NUM_ROUNDS = 10
MASK_32_BIT = 0xFFFFFFFF

def salsa_sequence(key, nonce, byte_len):
    def salsa_round(data, p, q, r, s):
        def rotate_left(val, shift):
            return (val << shift & MASK_32_BIT) | (val >> (32 - shift))

        data[q] ^= rotate_left(data[p] + data[s] & MASK_32_BIT, 7)
        data[r] ^= rotate_left(data[q] + data[p] & MASK_32_BIT, 9)
        data[s] ^= rotate_left(data[r] + data[q] & MASK_32_BIT, 13)
        data[p] ^= rotate_left(data[s] + data[r] & MASK_32_BIT, 18)

    def compute_block(key, nonce, blk_num):
        def bytes_to_ints(data):
            return [int.from_bytes(data[i:i+4], "little") for i in range(0, len(data), 4)]

        constant = bytes_to_ints(b"expand 32-byte k")
        key_ints = bytes_to_ints(key)
        nonce_ints = bytes_to_ints(nonce)
        
        original = [
            constant[0], *key_ints[:4], constant[1], *nonce_ints,
            blk_num & MASK_32_BIT, blk_num >> 32 & MASK_32_BIT,
            constant[2], *key_ints[4:], constant[3]
        ]
        transformed = original.copy()
        for _ in range(NUM_ROUNDS):
            for idx_set in [(0, 4, 8, 12), (5, 9, 13, 1), (10, 14, 2, 6), (15, 3, 7, 11),
                            (0, 1, 2, 3), (5, 6, 7, 4), (10, 11, 8, 9), (15, 12, 13, 14)]:
                salsa_round(transformed, *idx_set)
        
        return b"".join((a + b & MASK_32_BIT).to_bytes(4, "little") for a, b in zip(transformed, original))

    result = bytearray()
    blocks = [
        compute_block(key, nonce, count)[:min(byte_len, 64)]
        for count in range((byte_len + 63) // 64)
    ]
    result = bytearray().join(blocks)
    byte_len -= sum(map(len, blocks))

    return result

def encrypt(content: bytes, key: str, nonce: str) -> bytes:
    key = hashlib.sha256(key.encode('utf-8')).digest()
    nonce = nonce[:8].encode('utf-8')
    cipher_sequence = salsa_sequence(key, nonce, len(content))
    
    result = []
    for x, y in zip(content, cipher_sequence):
        result.append(x ^ y)
    return bytes(result)

def decrypt(content: bytes, key: str, nonce: str) -> bytes:
    return encrypt(content, key, nonce)
