import os
import random
import traceback
from mitmproxy import http

import sys
sys.path.append("..")  # Adds higher directory to python modules path. (Do not use .. in import)
from implementation.utils import get_preshared_key, encrypt, decrypt, write_error, get_headers_and_names, generate_nonce
from implementation.authentication.mac import generate_mac_sha1, generate_mac_hmac, get_string_to_auth
from implementation.key_exchange import request_certificate, create_certificate_response, send_session_key, create_acknowledgement_response
from datetime import datetime
import json

# Check if the errors directory exists
if not os.path.exists('errors'):
    os.mkdir('errors')

def check_encryption_method(method : str) -> bool:
    with open('./config.json', 'r') as file:
        data = json.load(file)
    return method in data["encryption"]["methods"]

def get_certificate_path():
    with open('./config.json', 'r') as file:
        data = json.load(file)
    if "sessions" in data:
        return data["sessions"]["path"] ,data["sessions"]["private_key_path"], data["sessions"]["cert_path"]
    return None, None, None, None

def check_authetication_method(method : str) -> bool:
    with open('./config.json', 'r') as file:
        data = json.load(file)
    return method in data["mac"]["methods"]

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

def Check_active_sessions(path : str):
    session_files = os.listdir(f"{path}/")
    for i in session_files:
        if not i.endswith(".json"):
            continue
        with open(path + '/' + i, 'r') as file:
            data = json.load(file)
        if "end" not in data or "id" not in data:
            continue
        if (data["end"]  - int(datetime.now().timestamp())) < 10:
            os.remove(path + '/' + i)
        else:
            return True, data["id"]
    return False, None

def retrieve_session(session_id: int):
    session_path, _, _ = get_certificate_path()
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
    
def authenticate_request(flow: http.HTTPFlow, method: str, key: str, nonce: str):
    auth_header = flow.request.headers.get("Authorization", "")

    parts = auth_header.split('mac="')
    original_mac = parts[1].split('"')[0]

    placeholder_header = auth_header.replace('mac="{}"'.format(original_mac), 'mac=""')
    flow.request.headers["Authorization"] = placeholder_header
    flow.request.headers["X-Authorization-Timestamp"] = str(int(datetime.now().timestamp()))

    string_to_auth = get_string_to_auth(flow.request)

    if method == "sha1":
        computed_mac = generate_mac_sha1(string_to_auth, key, nonce)
    elif method == "sha512hmac":
        computed_mac = generate_mac_hmac(string_to_auth, key, nonce)
    else:
        flow.response = http.Response.make(401, b"Not authorized", {"Content-Type": "text/plain",
                                                                                    "date": datetime.now().strftime(
                                                                                        "%a, %d %b %Y %H:%M:%S GMT"),
                                                                                    "connection": "close",
                                                                                    "WWW-Authenticate": method})
        return

    if computed_mac != original_mac:
        flow.response = http.Response.make(401, b"Not authorized", {"Content-Type": "text/plain",
                                                                                    "date": datetime.now().strftime(
                                                                                        "%a, %d %b %Y %H:%M:%S GMT"),
                                                                                    "connection": "close",
                                                                                    "WWW-Authenticate": method})


def authenticate_response(flow: http.HTTPFlow, method: str, key: str, nonce: str):
    header_names = get_headers_and_names(flow.request)
    placeholder_header = '{} keyid="{}", nonce="{}", headers="{}", mac="{}"'.format(method, key, nonce, header_names, "")
    flow.response.headers["Authorization"] = placeholder_header

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
        mac = generate_mac_sha1(string_to_auth, key, nonce)
    elif method == "sha512hmac":
        mac = generate_mac_hmac(string_to_auth, key, nonce)
    else:
        flow.response = http.Response.make(401, b"Not authorized", {"Content-Type": "text/plain",
                                                                    "date": datetime.now().strftime(
                                                                        "%a, %d %b %Y %H:%M:%S GMT"),
                                                                    "connection": "close",
                                                                    "WWW-Authenticate": method})
        return

    header_value = '{} keyid="{}", nonce="{}", headers="{}", mac="{}"'.format(method, key, nonce, header_names, mac)
    flow.request.headers["Authorization"] = header_value

def create_session_id(path: str):
    """
    Creates a session id and checks if it already exists.
    """
    session_id = random.randint(0, 99999)
    while os.path.exists(path + str(session_id)):
        session_id = random.randint(0, 99999)
    return session_id

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
    try:
        if 'http://cns_flaskr/' != flow.request.url[:18]:  # Checks if the traffic is meant for the falskr website
            return
        flow.comment = 'cns_flaskr'  # Somehow indicate the flow is about traffic from cns_flaskr

        # If the traffic is meant for the flaskr website, redirect it to the webserver (reverse proxy)
        flow.request.host = 'localhost'  # Important do not delete
        flow.request.port = 5000

        if flow.request.path == '/client_hello':
            flow.response = create_certificate_response()
            return

        encryption_method = flow.request.headers["Accept-Encoding"]
        key_id = get_key_id()
        key = get_preshared_key(key_id)
        auth_key = key
        rsa_keypath = get_rsa_private_keypath()
        path, private_key_path, cert_path = get_certificate_path()
        garbage_collection(path)

        if flow.request.path == '/client_ack':
            nonce = flow.request.headers["Nonce"]
            encrypted_session_key = decrypt(flow.request.raw_content, key, nonce, "rsa-oaep", rsa_keypath)
            if encrypted_session_key == None:
                flow.response = http.Response.make(400, b"Could not decrypt session key")
                return
            encryption_key = encrypted_session_key[:100]
            authentication_key = encrypted_session_key[100:]
            if isinstance(encryption_key, bytes):
                encryption_key = encryption_key.decode()
            if isinstance(authentication_key, bytes):
                authentication_key = authentication_key.decode()
            #create session file
            session_id = create_session_id(path)
            session_end = datetime.now().timestamp() + 60
            data = {"id" : session_id, "end" : session_end, "encr_key" : encryption_key, "auth_key" : authentication_key}
            sespath = f"{path}/session_{str(session_id)}.json"
            json.dump(data, open(sespath, 'w'))
            flow.response = create_acknowledgement_response(session_id, session_end)
            return

        nonce = flow.request.headers["Encryption"].split(',')[1].split(' ')[1].split('"')[1]
        active_session, session_id = Check_active_sessions(path)
        # auth_method = flow.request.headers["Authorization"].split(' ')[0]

        if active_session:
            session = retrieve_session(session_id)
            if session == None:
                flow.response = http.Response.make(400, b"Could not find session")
                return
            key = session["encr_key"]
            auth_key = session["auth_key"]
            if int(session["end"]) - datetime.now().timestamp() < 10:
                flow.response = http.Response.make(400, b"Session expired")
                return

        # authenticate_request(flow, auth_method,auth_key, nonce)

        # Replaces the value of a header
        # flow.request.headers['Accept-Encoding'] = str(flow.request.headers['Accept-Encoding']).replace(encryption_method, '')

        if len(flow.request.raw_content) > 0:
            flow.request.raw_content = decrypt(flow.request.raw_content, key, nonce,encryption_method, rsa_keypath)
        flow.request.set_content(flow.request.raw_content)
        # flow.request.headers["Accept-Encoding"] = encryption_method

        # If the traffic is meant for the flaskr website, redirect it to the webserver (reverse proxy)
        flow.request.host = 'localhost'  # Important do not delete
        flow.request.port = 5000

    except Exception as e:
        # Return an error reply to the client with the error message
        write_error(flow, 'Server side - Request:\n{}\n{}'.format(e, traceback.format_exc()))
        # Do not let the message go through to the website, nor the reverse proxy. Direct to random port
        flow.request.port = 5003


def response(flow: http.HTTPFlow) -> None:
    # If the response is an error message, return the message without performing any actions
    if flow.response.status_code >= 400:
        return
    try:
        if 'cns_flaskr' not in flow.comment:  # Checks if the traffic is meant for the falskr website
            return

        if "Encryption" not in flow.request.headers:
            return

        encryption_method = flow.request.headers["Accept-Encoding"]
        # auth_method = flow.request.headers["Authorization"].split(' ')[0]
        key_id = get_key_id()
        key = get_preshared_key(key_id)
        auth_key = key
        nonce = generate_nonce(encryption_method)
        rsa_keypath = get_rsa_public_keypath()
        path, private_key_path, cert_path = get_certificate_path()
        garbage_collection(path)
        active_session, session_id = Check_active_sessions(path)

        if active_session:
            session = retrieve_session(session_id)
            if session == None:
                flow.response = http.Response.make(400, b"Could not find session")
                return
            key = session["encr_key"]
            auth_key = session["auth_key"]
            key_id = session_id
            if int(session["end"]) - datetime.now().timestamp() < 10:
                flow.response = http.Response.make(400, b"Session expired")
                return

        if check_encryption_method(encryption_method) == False:
            flow.response.status_code = 400
            flow.response.reason = "Not a valid encoding method"
            return

        # if not check_authetication_method(auth_method):
        #     flow.response.status_code = 401
        #     flow.response.reason = "Not a valid authentication method"
        #     return

        if len(flow.response.raw_content) > 0:
            flow.response.raw_content = encrypt(flow.response.raw_content, key, nonce, encryption_method, rsa_keypath)
        flow.response.headers["Encryption"] = f"[ keyid=\"{key_id}\", nonce=\"{nonce}\", method=\"{encryption_method}\""
        flow.response.set_content(flow.response.raw_content)

        # authenticate_response(flow, auth_method, auth_key, nonce)


    except Exception as e:
        # Return an error reply to the client with the error message
        write_error(flow, 'Server side - Response:\n{}\n{}'.format(e, traceback.format_exc()))

