import os
import traceback
from mitmproxy import http

import sys
sys.path.append("..")  # Adds higher directory to python modules path. (Do not use .. in import)

from implementation.utils import get_preshared_key, encrypt, decrypt, write_error, get_headers_and_names, generate_nonce
from implementation.authentication.mac import generate_mac_sha1, generate_mac_hmac, get_string_to_auth
from datetime import datetime
from implementation.key_exchange import request_certificate, create_certificate_response, send_session_key, create_acknowledgement_response
from implementation.check_cert import check_certificate
import json

# Check if the errors directory exists
if not os.path.exists('errors'):
    os.mkdir('errors')


def get_encryption_method() -> str:
    with open('./config.json', 'r') as file:
        data = json.load(file)
    return data["encryption"]["method"]

def get_authetication_method() -> str:
    with open('./config.json', 'r') as file:
        data = json.load(file)
    return data["mac"]["method"]

def get_rsa_public_keypath() -> str:
    with open('./config.json', 'r') as file:
        data = json.load(file)
    return data["encryption"]["public_key_path"]

def get_rsa_private_keypath() -> str:
    with open('./config.json', 'r') as file:
        data = json.load(file)
    return data["encryption"]["private_key_path"]

def get_key_id() -> str:
    with open('./config.json', 'r') as file:
        data = json.load(file)
    return data["encryption"]["keyid"]

def get_certificate_path() -> str:
    with open('./config.json', 'r') as file:
        data = json.load(file)
    if "sessions" in data:
        return data["sessions"]["path"] ,data["sessions"]["cert_save_path"], data["sessions"]["ca_cert_path"], data["sessions"]["save_pub_key_path"]
    return None, None, None, None
    
def authenticate_request(flow: http.HTTPFlow, method: str, key: str, nonce: str):
    header_names = get_headers_and_names(flow.request)
    placeholder_header = '{} keyid="{}", nonce="{}", headers="{}", mac="{}"'.format(method, key, nonce, header_names, "")
    flow.request.headers["Authorization"] = placeholder_header
    flow.request.headers["X-Authorization-Timestamp"] = str(int(datetime.now().timestamp()))

    string_to_auth = get_string_to_auth(flow.request)

    if method == "sha1":
        mac = generate_mac_sha1(string_to_auth, key, nonce)
    elif method == "sha512hmac":
        mac = generate_mac_hmac(string_to_auth, key, nonce)
    else:
        flow.response = http.Response.make(401, b"Server response not authorized", {"Content-Type": "text/plain",
                                                                    "date": datetime.now().strftime(
                                                                        "%a, %d %b %Y %H:%M:%S GMT"),
                                                                    "connection": "close", "WWW-Authenticate": method})
        return

    header_value = '{} keyid="{}", nonce="{}", headers="{}", mac="{}"'.format(method, key, nonce, header_names, mac)
    flow.request.headers["Authorization"] = header_value

def authenticate_response(flow: http.HTTPFlow, method: str, key: str, nonce: str):
    auth_header = flow.request.headers.get("Authorization", "")

    parts = auth_header.split('mac="')
    original_mac = parts[1].split('"')[0]

    placeholder_header = auth_header.replace('mac="{}"'.format(original_mac), 'mac=""')
    flow.request.headers["Authorization"] = placeholder_header
    request_timestamp = int(flow.request.headers.get("X-Authorization-Timestamp", ""))
    current_time = int(datetime.now().timestamp())
    diff = int(current_time) - int(request_timestamp)
    if diff > 900:
        flow.response = http.Response.make(401, b"Not authorized", {"Content-Type": "text/plain",
                                                                    "date": datetime.now().strftime(
                                                                        "%a, %d %b %Y %H:%M:%S GMT"),
                                                                    "connection": "close",
                                                                    "WWW-Authenticate": method})
        return

    string_to_auth = get_string_to_auth(flow.request)

    if method == "sha1":
        computed_mac = generate_mac_sha1(string_to_auth, key, nonce)
    elif method == "sha512hmac":
        computed_mac = generate_mac_hmac(string_to_auth, key, nonce)
    else:
        flow.response = http.Response.make(401, b"Server response not authorized", {"Content-Type": "text/plain",
                                                                                    "date": datetime.now().strftime(
                                                                                        "%a, %d %b %Y %H:%M:%S GMT"),
                                                                                    "connection": "close",
                                                                                    "WWW-Authenticate": method})
        return

    if computed_mac != original_mac:
        flow.response = http.Response.make(401, b"Server response not authorized", {"Content-Type": "text/plain",
                                                                                    "date": datetime.now().strftime(
                                                                                        "%a, %d %b %Y %H:%M:%S GMT"),
                                                                                    "connection": "close",
                                                                                    "WWW-Authenticate": method})
def Check_active_sessions(path : str):
    session_files = os.listdir(path + '/')
    for i in session_files:
        if not i.endswith(".json"):
            continue
        with open(path + '/' + i, 'r') as file:
            data = json.load(file)
        if "end" not in data or "id" not in data:
            continue
        if (data["end"] - int(datetime.now().timestamp())) < 10:
            os.remove(path + '/' + i)
        else:
            return True, data["id"]
    return False, None

def random_100b_session_key():
    return os.urandom(50).hex()

def retrieve_session(session_id: int):
    session_path, cert_save_path, ca_cert_path, save_pub_key_path = get_certificate_path()
    session_files = os.listdir(session_path)
    for i in session_files:
        if not i.endswith(".json"):
            continue
        with open(session_path + '/' + i, 'r') as file:
            data = json.load(file)
        if "id" not in data:
            continue
        if data["id"] == session_id:
            return data
    return None

def garbage_collection(path: str):
    """
    Removes all expired sessions.
    """
    session_files = os.listdir(f"{path}/")
    for i in session_files:
        if not i.endswith(".json"):
            continue
        with open(path + '/' + i, 'r') as file:
            data = json.load(file)
        if "end" not in data or "id" not in data:
            continue
        if (data["end"] - int(datetime.now().timestamp())) < 10:
            os.remove(path + '/' + i)

def request(flow: http.HTTPFlow) -> None:
    try:  # Do not edit this line
        if 'http://cns_flaskr/' != flow.request.url[:18]:  # Checks if the traffic is meant for the falskr website
            return
        flow.comment = 'cns_flaskr'  # Somehow indicate the flow is about traffic from cns_flaskr

        encryption_method = get_encryption_method()
        auth_method = get_authetication_method()
        key_id = get_key_id()
        key = get_preshared_key(key_id)
        auth_key = key
        rsa_keypath = get_rsa_public_keypath()
        nonce = generate_nonce(encryption_method)

        # Check for active sessions in session directory
        session_path, cert_save_path, ca_cert_path, save_pub_key_path = get_certificate_path()
        garbage_collection(session_path)
        if session_path is not None:
            active_session, session_id = Check_active_sessions(session_path)
            if not active_session:
                # Request a certificate from the server
                request_certificate()
                # verify the certificate
                if not check_certificate(cert_save_path, ca_cert_path, save_pub_key_path):
                    flow.response = http.Response.make(496, b"SSL Certificate Required", {"Content-Type": "text/plain"})
                    return
                # Send the session key to the server
                encryption_key = random_100b_session_key()
                authentication_key = random_100b_session_key()
                session_key = encryption_key + authentication_key
                rsa_nonce = generate_nonce("rsa-oaep")
                session_key_encrypted = encrypt(session_key.encode(), key, rsa_nonce, "rsa-oaep", save_pub_key_path)
                session_response = send_session_key(session_key_encrypted, {"Nonce": rsa_nonce})
                session_id = int(session_response.content[:5])
                session_end = float(session_response.content[5:])
                # Create a session file
                session = {"id": session_id, "end": session_end, "encr_key": encryption_key, "auth_key": authentication_key}
                sespath = f"{session_path}/session_{str(session_id)}.json"
                json.dump(session, open(sespath, 'w'))
            else:
                session = retrieve_session(session_id)
                if session is None:
                    flow.response = http.Response.make(400, b"No active session present", {"Content-Type": "text/plain"})
                    return
                key = session["encr_key"]
                auth_key = session["auth_key"]
                key_id = session_id

        if 'Accept-Encoding' in flow.request.headers:
            flow.request.headers['Accept-Encoding'] = encryption_method
        else:
            flow.request.headers.insert(0, 'Accept-Encoding', encryption_method)  # Headers are always strings
        if len(flow.request.raw_content) > 0:
            flow.request.raw_content = encrypt(flow.request.raw_content, key, nonce, encryption_method, rsa_keypath)
        flow.request.headers["Encryption"] = f"[ keyid=\"{key_id}\", nonce=\"{nonce}\", method=\"{encryption_method}\""
        flow.request.set_content(flow.request.raw_content)

        # authenticate_request(flow, auth_method, auth_key, nonce)

    except Exception as e:
        # Return an error reply to the client with the error message
        write_error(flow, 'Client side - Request:\n{}\n{}'.format(e, traceback.format_exc()))

def response(flow: http.HTTPFlow) -> None:
    # If the response is an error message, return the message without performing any actions
    if flow.response.status_code >= 400:
        return
    
    if "X-Authenticated-Id" in flow.response.headers:
        flow.response = http.Response.make(401, b"unauthenticated", {"Content-Type": "text/plain"})
        return
    
    try:
        if 'cns_flaskr' not in flow.comment:  # Checks if the traffic is meant for the falskr website
            return
        

        encryption_method = flow.request.headers["Accept-Encoding"]
        auth_method = get_authetication_method()
        key_id = get_key_id()
        key = get_preshared_key(key_id)
        nonce = flow.response.headers["Encryption"].split(',')[1].split(' ')[1].split('"')[1]
        rsa_keypath = get_rsa_private_keypath()
        session_path, cert_save_path, ca_cert_path, save_pub_key_path = get_certificate_path()
        garbage_collection(session_path)

        # authenticate_response(flow, auth_method, key, nonce)

        # if 'Accept-Encoding' in flow.response.headers:  # Checks if a header is present
        #     # Replaces the value of a header
        #     flow.response.headers['Accept-Encoding'] = str(flow.response.headers['Accept-Encoding']).replace(encryption_method, '')

        active_session, session_id = Check_active_sessions(session_path)
        if active_session:
            session = retrieve_session(session_id)
            if session is None:
                flow.response = http.Response.make(400, b"No active session present", {"Content-Type": "text/plain"})
                return
            key = session["encr_key"]
            auth_key = session["auth_key"]

        if 'Accept-Encoding' not in flow.request.headers:
            flow.response.status_code = 400
            flow.response.reason = "Not a valid encoding method"
            return

        if len(flow.response.raw_content) > 0:
            flow.response.raw_content = decrypt(flow.response.raw_content, key, nonce, encryption_method, rsa_keypath)
        flow.response.set_content(flow.response.raw_content)


    except Exception as e:
        # Return an error reply to the client with the error message
        write_error(flow, 'Client side - Response:\n{}\n{}'.format(e, traceback.format_exc()))

