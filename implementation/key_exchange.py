# DO NOT CHANGE ANYTHING IN THIS FILE
# If you think something should be changed -> contact us!

import requests
from mitmproxy import http


url = 'http://cns_flaskr/'


# output_path = path to the location where the server certificate will be saved
def request_certificate(output_path: str = 'keys/cns_flaskr.crt') -> str:
    path = 'client_hello'

    session = requests.Session()
    session.trust_env = False  # Skip the proxy
    response = session.get(url + path)

    open(output_path, 'wb').write(response.content)
    return output_path


def create_certificate_response() -> http.Response:
    return http.Response.make(200, open('keys/cns_flaskr.crt', 'rb').read())


# encrypted_session_key = with rsa encrypted session key
# needed_headers = all needed headers needed to decrypt the session key
# return = response of the server in the mitmproxy http.Response class
def send_session_key(encrypted_session_key: bytes, needed_headers: dict) -> http.Response:
    path = 'client_ack'
    session = requests.Session()
    session.trust_env = False
    response = session.post(url + path, data=encrypted_session_key, headers=needed_headers)
    if response.status_code != 200:
        raise Exception('Something went wrong in the session information exchange')

    temp_response = http.Response.make(200)
    temp_response.content = response.content
    for h in response.headers.keys():
        if h in temp_response.headers:
            temp_response.headers[h] = response.headers[h]
        else:
            temp_response.headers.insert(-1, h, response.headers[h])

    return temp_response


# session_end = unix timestamp of the end of the session
def create_acknowledgement_response(session_id: int, session_end: float):
    assert session_id < 100000
    return http.Response.make(200, '{:05d}{}'.format(session_id, session_end))
