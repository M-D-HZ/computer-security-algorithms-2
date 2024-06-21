from Crypto.Cipher import AES
import hashlib
import struct
import base64

def generate_key(key: str) -> bytes:
    return hashlib.sha256(key.encode()).digest()

def encrypt(content: bytes, key: str, nonce: str) -> bytes:
    aes_key = generate_key(key)
    iv = nonce.encode()[:16]
    
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    
    pad_length = 16 - (len(content) % 16)
    content += bytes([pad_length] * pad_length)
    encrypted_content = cipher.encrypt(content)
    
    return encrypted_content

def decrypt(content: bytes, key: str, nonce: str) -> bytes:
    aes_key = generate_key(key)
    iv = nonce.encode()[:16]
    
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    
    decrypted_content = cipher.decrypt(content)
    
    pad_length = decrypted_content[-1]
    decrypted_content = decrypted_content[:-pad_length]
    
    return decrypted_content
