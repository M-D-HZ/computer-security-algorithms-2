import os
from mitmproxy import http
from implementation.encryption import aes, salsa, rsa

def example_function():
    pass


def write_error(flow: http.HTTPFlow, error: str) -> None:
    i = 0
    while os.path.exists('errors/error_{}.txt'.format(i)):
        i += 1
    open('errors/error_{}.txt'.format(i), 'w').write(error)
    flow.comment = 'ERROR: {}'.format(error)
    flow.response = http.Response.make(500, flow.comment[7:])


def get_preshared_key(key_id: str) -> str:
    with open(key_id, 'r') as f:
        return f.read()

def encrypt(content: bytes, key: str, nonce: str, method, rsa_key_path: str):
    if method == 'aes256cbc':
        return aes.encrypt(content, key, nonce)
    elif method == 'salsa20':
        return salsa.encrypt(content,key,nonce)
    elif method == 'rsa-oaep':
        return rsa.encrypt(content,rsa_key_path,nonce)

def decrypt(content: bytes, key: str, nonce: str, method, rsa_key_path: str):
    if method == 'aes256cbc':
        return aes.decrypt(content, key, nonce)
    elif method == 'salsa20':
        return salsa.decrypt(content,key,nonce)
    elif method == 'rsa-oaep':
        return rsa.decrypt(content,rsa_key_path,nonce)

def generate_nonce(method: str) -> str:
    nonce_size = 0
    if method == 'aes256cbc':
        nonce_size = 8
    elif method == 'salsa20':
        nonce_size = 4
    elif method == 'rsa-oaep':
        nonce_size = 10
    return os.urandom(nonce_size).hex()
    
def get_headers_and_names(request) -> (str, str):
    header_names = sorted([name.lower() for name in request.headers.keys()])
    header_names_str = ";".join(header_names)
    return header_names_str
