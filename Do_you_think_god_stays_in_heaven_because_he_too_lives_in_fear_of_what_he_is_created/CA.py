import datetime
import socket
import ssl
import threading
import logging

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives._serialization import Encoding
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_private_key():
    try:
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
    except Exception as e:
        logging.error(f"Error generating private key: {e}")
        raise


def self_sign_certificate(private_key, common_name):
    try:
        subject = x509.Name([
            x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "PL"),
            x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, "Lubelskie"),
            x509.NameAttribute(x509.NameOID.LOCALITY_NAME, "Lublin"),
            x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "Lobotomia Inc."),
            x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name),
        ])

        builder = x509.CertificateBuilder()
        builder = builder.subject_name(subject)
        builder = builder.issuer_name(subject)
        builder = builder.public_key(private_key.public_key())
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.not_valid_before(datetime.datetime.utcnow())
        builder = builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True,
        )

        certificate = builder.sign(
            private_key=private_key,
            algorithm=hashes.SHA256(),
            backend=default_backend(),
        )

        return certificate
    except Exception as e:
        logging.error(f"Error self-signing certificate: {e}")
        raise


def sign_certificate(ca_certificate, ca_private_key, certificate_request):
    try:
        subject = certificate_request.subject
        public_key = certificate_request.public_key()

        builder = x509.CertificateBuilder()
        builder = builder.subject_name(subject)
        builder = builder.issuer_name(ca_certificate.subject)
        builder = builder.public_key(public_key)
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.not_valid_before(datetime.datetime.utcnow())
        builder = builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))

        certificate = builder.sign(
            private_key=ca_private_key,
            algorithm=hashes.SHA256(),
            backend=default_backend(),
        )

        return certificate
    except Exception as e:
        logging.error(f"Error signing certificate: {e}")
        raise


def handle_request(client_socket, ca_certificate, ca_private_key):
    try:
        csr_pem = client_socket.recv(4096)
        csr = x509.load_pem_x509_csr(csr_pem, default_backend())
        signed_certificate = sign_certificate(ca_certificate, ca_private_key, csr)
        client_socket.sendall(signed_certificate.public_bytes(Encoding.PEM))
        client_socket.sendall(ca_certificate.public_bytes(Encoding.PEM))
    except Exception as e:
        logging.error(f"Error handling client request: {e}")
        client_socket.sendall(b"Error processing request")
    finally:
        client_socket.close()


def save_key_to_file_using_pem(key, filename):
    try:
        with open(f"{filename}.key", "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
    except Exception as e:
        logging.error(f"Error saving key to file: {e}")
        raise


def save_cert_to_file_using_pem(cert, filename):
    try:
        with open(f"{filename}.crt", "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
    except Exception as e:
        logging.error(f"Error saving certificate to file: {e}")
        raise


def read_key_from_file_using_pem(filename):
    try:
        with open(f"{filename}.key", "rb") as f:
            data = f.read()
            return serialization.load_pem_private_key(data, password=None, backend=default_backend())
    except Exception as e:
        logging.error(f"Error reading key from file: {e}")
        raise


def read_cert_from_file_using_pem(filename):
    try:
        with open(f"{filename}.crt", "rb") as f:
            data = f.read()
            return x509.load_pem_x509_certificate(data, backend=default_backend())
    except Exception as e:
        logging.error(f"Error reading certificate from file: {e}")
        raise


def client_handler(client_socket, ca_certificate, ca_private_key):
    handle_request(client_socket, ca_certificate, ca_private_key)


def main():
    logging.basicConfig(level=logging.INFO)
    ca_host = 'localhost'
    ca_port = 7070

    try:
        private_ca_key = generate_private_key()
        ca_cert = self_sign_certificate(private_ca_key, 'ca.com')

        save_key_to_file_using_pem(private_ca_key, 'ca')
        save_cert_to_file_using_pem(ca_cert, 'ca')
        ca_cert = read_cert_from_file_using_pem('ca')
        private_ca_key = read_key_from_file_using_pem('ca')
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile="ca.crt", keyfile="ca.key")

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.bind((ca_host, ca_port))
            server_socket.listen(5)
            logging.info(f"Server listening on {ca_host}:{ca_port}")

            with context.wrap_socket(server_socket, server_side=True) as ssl_socket:
                while True:
                    try:
                        client_socket, addr = ssl_socket.accept()
                        logging.info(f"Connection from {addr}")

                        client_thread = threading.Thread(target=client_handler, args=(client_socket, ca_cert, private_ca_key))
                        client_thread.start()
                    except Exception as e:
                        logging.error(f"Error accepting connection: {e}")
    except Exception as e:
        logging.error(f"Server setup failed: {e}")


if __name__ == "__main__":
    main()
