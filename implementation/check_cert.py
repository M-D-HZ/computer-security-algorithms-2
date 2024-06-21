import OpenSSL


def check_certificate(checked_crt: str, ca_crt: str, public_key_output_path: str):
    """
    Checks if the certificate is valid for x509 certificates making use of the pyOpenSSL library
    :param checked_crt: path to the certificate that should be checked
    :param ca_crt: path to the ca certificate
    :param public_key_output_path: path to the location where the public key should be saved
    :return: True if the certificate is valid, False otherwise
    """
    try:
        # Load the certificate
        cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, open(checked_crt, 'rb').read())
        # Load the CA certificate
        ca = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, open(ca_crt, 'rb').read())
        # Create a store and add the CA certificate
        store = OpenSSL.crypto.X509Store()
        store.add_cert(ca)
        # Create a certificate context using the store and the downloaded certificate
        store_ctx = OpenSSL.crypto.X509StoreContext(store, cert)
        # Verify the certificate, returns None if it can validate the certificate
        store_ctx.verify_certificate()
        # Save the public key
        open(public_key_output_path, 'wb').write(OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_PEM, cert.get_pubkey()))
        return True
    except Exception as e:
        return False

if __name__ == "__main__":
    print(check_certificate("cns_flaskr.crt", "ca.crt", "public_key.pem"))