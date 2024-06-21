import hashlib

from mitmproxy import http
from .sha1 import SHA1

# Return mac as str in hex format generated with SHA-1
def generate_mac_sha1(content: bytes, key: str, nonce: str) -> str:
    sha1 = SHA1()
    data = key.encode() + nonce.encode() + content
    sha1.hash(data.decode())
    return sha1.hexdigest()


# Return mac as str in hex format generated with HMAC-SHA512
def generate_mac_hmac(content: bytes, key: str, nonce: str) -> str:
    key = key.encode()
    block_size = 128
    iPad = b'\x36' * block_size
    oPad = b'\x5c' * block_size

    if len(key) > block_size:
        key = hashlib.sha512(key).digest()
    elif len(key) < block_size:
        key = key + bytes([0x00] * (block_size - len(key)))

    if len(nonce) < 128:
        nonce = nonce.ljust(128, '\x00')
    else:
        nonce = nonce[:128]

    i_Pad = bytes(x ^ y for x,y in zip(key, iPad))
    o_Pad = bytes(x ^ y for x,y in zip(key, oPad))


    hmac = hashlib.sha512(o_Pad + hashlib.sha512(i_Pad + nonce.encode() + content).digest()).hexdigest()
    return hmac


# Returns the string to authenticate of the given message
def get_string_to_auth(message: http.Message) -> bytes:
    # Handle http.Request objects
    # Handle http.Request objects
    # Handle http.Request objects
    # Initialize the string to authenticate
    string_to_auth = ""

    # Handle http.Request objects
    if isinstance(message, http.Request):
        string_to_auth += message.method.upper() + "\n" + message.host + "\n" + message.path + "\n"
    else:  # For responses, according to the description there should not be these parts
        string_to_auth += "\n\n\n"

    # Extract headers excluding 'x-authenticated-id'
    header_parts = []
    for header_name, header_value in message.headers.items():
        if header_name.lower() != 'x-authenticated-id':
            header_parts.append(header_name.lower() + ":" + header_value)

    # Sort the headers and join them
    header_parts.sort()
    string_to_auth += '\n'.join(header_parts)

    # Check for content and append if present
    content_length = message.headers.get('Content-Length', '0')
    if content_length.isdigit() and int(content_length) > 0:
        string_to_auth += '\n' + message.raw_content.decode('utf-8', 'ignore')
    else:
        string_to_auth += '\n'

    return string_to_auth.encode()
