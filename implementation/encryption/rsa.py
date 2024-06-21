import os
import random
import math

from Crypto.PublicKey import RSA
import hashlib


def power_eme(a: int, b: int, n: int) -> int:
    """
    a^b mod n calculation (p40 in 1st assymmetric decryption lecture)
    :param a: base
    :param b: exponent
    :param n: modulus
    :return: a^b mod n
    """
    f = 1
    b = bin(b)[2:]  # convert b to binary (cut off 0b)
    k = len(b)
    for i in range(k):
        f = (f * f) % n
        if b[i] == '1':
            f = (f * a) % n
    return f


def rabin_miller_test(n: int, d: int) -> bool:
    """
    Rabin-Miller primality test
    :param n: number to test
    :param d: n - 1
    :return: True if n is prime, False otherwise
    """
    a = random.randint(2, n - 2)
    x = power_eme(a, d, n)
    if x == 1 or x == n - 1:
        return True
    while d != n - 1:
        x = (x * x) % n
        d *= 2
        if x == 1:
            return False
        if x == n - 1:
            return True
    return False

def is_prime(n: int, k: int) -> bool:
    """
    Prime checker using Rabin-Miller primality test
    :param n: number to test
    :param k: number of iterations
    :return: True if n is prime, False otherwise
    """
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    d = n - 1  # n - 1 = 2^k * d
    while d % 2 == 0:
        d //= 2
    for _ in range(k):
        if not rabin_miller_test(n, d):
            return False
    return True

def generate_prime_nr(nr_bits: int) -> int:
    """
    Generate a prime number with nr_bits bits
    :param nr_bits: number of bits
    :return: prime number with nr_bits bits
    """
    while True:
        n = random.getrandbits(nr_bits)
        n |= (1 << nr_bits - 1) | 1
        if is_prime(n, 100):
            return n


def gcd(a: int, b: int) -> int:
    """
    Greatest common divisor
    :param a: first number
    :param b: second number
    :return: greatest common divisor
    """
    while b != 0:
        a, b = b, a % b
    return a

def non_recursion_extended_gcd(a: int, b: int) -> (int, int, int):
    """
    Extended Euclidean algorithm
    :param a: first number
    :param b: second number
    :return: (gcd(a, b), x, y) where x and y are Bezout coefficients
    """
    x, y = 0, 1
    last_x, last_y = 1, 0
    while b != 0:
        q = a // b
        a, b = b, a % b
        x, last_x = last_x - q * x, x
        y, last_y = last_y - q * y, y
    return a, last_x, last_y

def multiplicative_inverse(a: int, n: int) ->  int | None:
    """
    Multiplicative inverse of a modulo n
    :param a: number
    :param n: modulo
    :return: multiplicative inverse of a modulo n
    """
    g, x, _ = non_recursion_extended_gcd(a, n)
    if g == 1:
        return x % n
    return None

def generate_keys(private_key_path: str, public_key_path: str, nr_bits: int) -> None:
    """
    Generate RSA keys (p26,p29 in assymmetric encryption lecture  )
    :param private_key_path: path to private key
    :param public_key_path: path to public key
    :param nr_bits: number of bits
    :return: None
    """
    assert nr_bits in [1024, 2048, 4096], "number of bits not allowed"
    assert private_key_path.endswith('.pem'), "Incorrect file type"
    assert public_key_path.endswith('.pem'), "Incorrect file type"

    p = generate_prime_nr(nr_bits//2)
    q = generate_prime_nr(nr_bits//2)
    n = p * q
    e = random.randint(2, (p-1)*(q-1))
    if nr_bits != 1024:
        while gcd(e, (p-1)*(q-1)) != 1:
            e = random.randint(2, (p-1)*(q-1))
            d = multiplicative_inverse(e, (p - 1) * (q - 1))
            if d == e:  # d == e means that e is not invertible
                continue
    else:
        e = 65537
        d = multiplicative_inverse(e, (p - 1) * (q - 1))

    private_key = RSA.construct((n, e, d, p, q))
    private_key_pem = private_key.exportKey()
    open(private_key_path, 'wb').write(private_key_pem)
    public_key = RSA.construct((n, e))
    public_key_pem = public_key.exportKey()
    open(public_key_path, 'wb').write(public_key_pem)


def I2OSP(x: int, x_len: int) -> bytes:
    """
    Integer to octet string primitive
    :param x: integer
    :param x_len: length of octet string
    :return: octet string
    """
    assert x < 256 ** x_len, "integer too large"
    return x.to_bytes(x_len, 'big')

def OS2IP(x: bytes) -> int:
    """
    Octet string to integer primitive
    :param x: octet string
    :return: integer
    """
    return int.from_bytes(x, 'big')

def MGF(seed: bytes, mask_len: int) -> bytes:
    """
    Mask generation function
    :param seed: seed
    :param mask_len: length of mask
    :return: mask
    """
    Lhash = hashlib.sha1("".encode()).digest()
    T = b''
    assert mask_len < (2**32) * len(Lhash), "mask too long"

    for x in range(math.ceil(mask_len / len(Lhash))):
        T += hashlib.sha1(seed + I2OSP(x,4)).digest()

    return T[:mask_len]

def RSAEP(m: int, e: int, n: int) -> int:
    """
    RSA encryption primitive
    :param m: message
    :param e: public exponent
    :param n: modulus
    :return: ciphertext
    """
    assert 0 <= m <= n, "Encryption error"
    return power_eme(m, e, n)

def RSADP(c: int, d: int, n: int) -> int:
    """
    RSA decryption primitive
    :param c: ciphertext
    :param d: private exponent
    :param n: modulus
    :return: message
    """
    assert 0 <= c <= n, "decryption error"
    return power_eme(c, d, n)

def encrypt(content: bytes, key_path: str, nonce: str) -> bytes:
    """
    Encrypt content using RSA (https://datatracker.ietf.org/doc/html/rfc8017#autoid-19)
    :param content: content to encrypt
    :param key_path: path to public key
    :param nonce: nonce
    :return: encrypted content
    """
    assert len(content) >= 0, "Encryption error"

    with open(key_path, 'rb') as f:
        public_key = RSA.importKey(f.read())
    n = public_key.n
    k = math.ceil(len(bin(n)[2:]) / 8)   # number of bytes in n

    Lhash = hashlib.sha1("".encode()).digest()
    block_size = k - 2 * len(Lhash) - 2

    assert block_size >= 0, "Encryption error"

    content_blocks = [content[i:min(i+block_size, len(content))] for i in range(0, len(content), block_size)]
    encryption = b''.join([RSAES_OAEP_encrypt(block, key_path, nonce) for block in content_blocks])
    return encryption


def RSAES_OAEP_encrypt(content: bytes, key_path: str, nonce: str) -> bytes:
    """
    Encrypt content using RSA (https://datatracker.ietf.org/doc/html/rfc8017#autoid-19)
    :param content: content to encrypt
    :param key_path: path to public key
    :param nonce: nonce
    :return: encrypted content
    """
    with open(key_path, 'rb') as f:
        public_key = RSA.importKey(f.read())
    n = public_key.n
    e = public_key.e
    k = math.ceil(n.bit_length() / 8)   # number of bytes in n

    # Step 1: EME-OAEP encoding
    Lhash = hashlib.sha1("".encode()).digest()
    # padding
    PS = b'\x00' * (k - len(content) - 2 * len(Lhash) - 2)
    # data block
    DB = Lhash + PS + b'\x01' + content
    assert len(DB) == k - len(Lhash) - 1, "Encryption error"
    # random octet string of seed length (len(Lhash), in our case the nonce will be the seed)
    seed = nonce.encode()
    # mask generation function
    dbMask = MGF(seed, k - len(Lhash) - 1)
    # XOR DB and dbMask
    maskedDB = bytes([x ^ y for x, y in zip(DB, dbMask)])
    # mask generation function (for seed)
    seedMask = MGF(maskedDB, len(Lhash))
    # XOR seed and seedMask
    maskedSeed = bytes([x ^ y for x, y in zip(seed, seedMask)])
    # concatenate maskedSeed and maskedDB
    EM = b'\x00' + maskedSeed + maskedDB
    assert len(EM) == k, "Encryption error"

    # Step 2: RSA encryption

    # convert EM to integer
    m = OS2IP(EM)
    # apply RSAEP encryption primitive
    c = RSAEP(m, e, n)
    # convert c to ciphertext
    C = I2OSP(c, k)
    assert len(C) == k, "Encryption error"

    return C

def decrypt(content: bytes, key_path: str, nonce: str) -> bytes:
    """
    Decrypt content using RSA (https://datatracker.ietf.org/doc/html/rfc8017#autoid-19)
    :param content: content to decrypt
    :param key_path: path to private key
    :param nonce: nonce
    :return: decrypted content
    """
    with open(key_path, 'rb') as f:
        private_key = RSA.importKey(f.read())
    n = private_key.n

    k = math.ceil(len(bin(n)[2:]) / 8)   # number of bytes in n

    blocks = [content[i:min(i+k,len(content))] for i in range(0, len(content), k)]

    return b''.join([RSAES_OAEP_decrypt(block, key_path, nonce) for block in blocks])

def RSAES_OAEP_decrypt(content: bytes, key_path: str, nonce: str) -> bytes:
    """
    Decrypt content using RSA (https://datatracker.ietf.org/doc/html/rfc8017#autoid-19)
    :param content: content to decrypt
    :param key_path: path to private key
    :param nonce: nonce
    :return: decrypted content
    """
    with open(key_path, 'rb') as f:
        private_key = RSA.importKey(f.read())
    n = private_key.n
    d = private_key.d

    k = math.ceil(len(bin(n)[2:]) / 8)  # number of bytes in n

    # Step 1: RSA decryption

    # convert content to integer
    c = OS2IP(content)
    # apply RSADP decryption primitive
    m = RSADP(c, d, n)
    # convert m to EM
    EM = I2OSP(m, k)

    # Step 2: EME-OAEP decoding
    Lhash = hashlib.sha1("".encode()).digest()
    # separate EM into maskedSeed and maskedDB
    Y = EM[0]
    maskedSeed = EM[1:len(Lhash) + 1]
    maskedDB = EM[len(Lhash) + 1:]
    # mask generation function (for seed)
    seedMask = MGF(maskedDB, len(Lhash))
    # XOR maskedSeed and seedMask
    # seed = bytes([x ^ y for x, y in zip(maskedSeed, seedMask)])
    seed = nonce.encode()
    # mask generation function (DbMask)
    dbMask = MGF(seed, k - len(Lhash) - 1)
    # XOR maskedDB and dbMask
    DB = bytes([x ^ y for x, y in zip(maskedDB, dbMask)])
    # separate DB into lHash, PS and M
    lHash = DB[:len(Lhash)]
    PS = DB[len(Lhash):].split(b'\x01')[0]
    M = DB[len(Lhash) + len(PS) + 1:]

    # check if lHash is equal to Lhash, check if Y is equal to 0, check if PS is equal to 0
    assert lHash == Lhash, "decryption error"
    assert Y == 0, "decryption error"
    assert PS == b'\x00' * (k - len(M) - 2 * len(Lhash) - 2), "decryption error"

    return M


if __name__ == "__main__":
    key = "keys/cns_flaskr_pub.pem"
    dkey = "./rsa_tests/cns_client_pri.pem"
    nonce = 'fa6bfe0d3f779a2f956a'
    plaintext = b'50d3fdebdf58a4f438a9f77b5f74f7d0e617414d6d349e71ecc23f7dea00d94274aff373d68b40e56d51e11a8900586478d5678f55791d056081402b16acc090719ce9ca43a8bd93a4ce411e5f11e9df353e7ff712f6761a77d51d46661f8c8cccb21db4b68fa42b40c4d98117d187f9b1d720eb26356ae0309f774e9e38aef8162a2214167d67b6ed0cee3ad2db4f71908b06b54d0ce7dc33f7dea5abb23bb10bfd112e7dea2d077ae3ad0eb6a7eaf1d83bff47edbc5ed541f32730ae1361480a0f4ef34d4ef7c8'
    ciphertext1 = encrypt(plaintext, key, nonce)
    print("Encryped text: ")
    print(ciphertext1)
    # decryptedtext1 = decrypt(ciphertext1, dkey, nonce)
    # print("Decrypted text: ")
    # print(decryptedtext1)
    # print("correct ciphertext: ")
    # ciphertext = b'?\x11\x88\xfe*\x9c\xe6\x00\x1c\xc9b\x8byy\x18\x0c<\xc5\x16\xe5\xf2Ds\x87o\xa0\xa9\x03\xbd\\\xc0\x91\'\xd7\x94\xed\xf98\r \x1eD\xe6\xdf\x13\x96q\xd0\xcc\xa4\x82\xa6\xb6s\xf2\xf5]X\xff\x1e8\x12\xa2 \xa5\xac\xf4\xbe\x05D\x97\xe6\x86H\x18-:\xa0\xc7\xfcvNI\x8b\x83Y\xd3\xff\xaf%\xf1\x83\xec\xa2\xd1\xf6D\xaf\xf7bY|\x18\xe7\xb2\xf5\xf2"y\r\x96\x98\x8cX\x13\xa7\xba\xc4+\xd8\xa0\xe3m#f\x16\xac\xb9'
    # print(ciphertext)
    # generate_keys("../../ca/ca_pri.pem", "./keys/ca_pu.pem", 2048)
