import json
import socket
import ssl
import threading
from hashlib import sha256

from Crypto.Cipher import AES
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_private_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )


def generate_csr(private_key, common_name):
    subject = x509.Name([
        x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(x509.NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "Example Inc."),
        x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name),
    ])
    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(subject)
    return builder.sign(private_key, hashes.SHA256(), default_backend())


def save_key_to_file_using_pem(key, filename):
    with open(f"{filename}.key", "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
        f.close()


def save_cert_to_file_using_pem(cert, filename):
    with open(f"{filename}.crt", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
        f.close()


def sign_csr(ca_host, ca_port):
    # Generate private key and CSR
    private_key = generate_private_key()
    csr = generate_csr(private_key, "client2.com")
    save_key_to_file_using_pem(private_key, 'client2')
    # Connect to CA client2
    with socket.create_connection((ca_host, ca_port)) as ca_socket:
        # Wrap the socket for SSL
        with ssl.wrap_socket(ca_socket, ssl_version=ssl.PROTOCOL_TLS) as ssl_ca_socket:
            # Send CSR
            ssl_ca_socket.sendall(csr.public_bytes(encoding=serialization.Encoding.PEM))
            # Receive signed certificate
            signed_cert_pem = ssl_ca_socket.recv(4096)
            ca_cert = ssl_ca_socket.recv(4096)
            with open(f"client2.crt", "wb") as f:
                f.write(signed_cert_pem)
                f.close()
            with open(f"client2_ca.crt", "wb") as f:
                f.write(ca_cert)
                f.close()


def generate_AES_key(s):
    dh_s_bytes = s.to_bytes((s.bit_length() + 7) // 8, 'big')

    s_sha256 = sha256(dh_s_bytes)
    s_sha256 = s_sha256.digest()

    AES_key = s_sha256[:16]
    return AES_key


def encrypt(key, plaintext):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return ciphertext, tag, nonce


def decrypt(key, ciphertext, tag, nonce):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    try:
        cipher.verify(tag)
        return plaintext
    except ValueError:
        print("Key incorrect or message corrupted")


def connect_waiting(server_socket, ip, port):
    try:
        print('ipw', ip, port)
        friend_waiting_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        friend_waiting_context.load_cert_chain(certfile="client2.crt", keyfile="client2.key")
        friend_waiting_context.load_verify_locations(cafile="client2_ca.crt")
        friend_waiting_context.verify_mode = ssl.CERT_REQUIRED
        friend_waiting_context.check_hostname = False

        friend_waiting_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        friend_waiting_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        friend_waiting_socket.bind((ip, int(port)))
        print('Bound to IP', ip, 'Port', port)
        friend_waiting_socket.listen(5)

        with friend_waiting_socket:
            with friend_waiting_context.wrap_socket(friend_waiting_socket,
                                                    server_side=True) as ssl_friend_waiting_socket:
                friend_socket, friend_address = ssl_friend_waiting_socket.accept()
                with friend_socket:
                    friend_username = friend_socket.recv(4096).decode()
                    friend_ip, friend_port = friend_socket.getpeername()
                    print('Received connection from', friend_ip, friend_port)
                    server_socket.sendall('cc'.encode())
                    server_socket.sendall(f'{friend_username}'.encode())

                    real_friend_ip = server_socket.recv(4096).decode()
                    real_friend_ip = server_socket.recv(4096).decode()

                    if real_friend_ip == 'w':

                        friend_socket.close()

                    else:
                        print(friend_ip, real_friend_ip)
                        if friend_ip != real_friend_ip:

                            friend_socket.close()
                        else:

                            friend_socket.sendall('ping'.encode())
                            print(friend_socket.recv(4096).decode())
                            friend_socket.close()
    except Exception as e:
        print(f"Error in connect_waiting: {e}")


def main():
    ca_host = 'localhost'
    ca_port = 7070

    sign_csr(ca_host, ca_port)
    server_host = 'localhost'
    server_port = 6969
    server_name = "server.com"

    # Utwórz kontekst SSL/TLS dla klienta
    client2_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    client2_context.load_cert_chain(certfile="client2.crt", keyfile="client2.key")

    # Wymaga weryfikacji certyfikatu serwera podpisanego przez zaufane CA
    client2_context.check_hostname = True
    client2_context.verify_mode = ssl.CERT_REQUIRED

    # client2_context.load_verify_locations(cafile="ca.crt")
    client2_context.load_verify_locations(cafile="client2_ca.crt")

    # Create a synchronization event
    login_event = threading.Event()

    # Utwórz połączenie TCP i nawiaż połączenie SSL/TLS z serwerem
    with socket.create_connection((server_host, server_port)) as client2_socket:

        local_ip, local_port = client2_socket.getsockname()
        print('local', local_ip, local_port)
        with client2_context.wrap_socket(client2_socket, server_hostname=server_name) as ssl_socket:
            ssl.match_hostname(ssl_socket.getpeercert(), server_name)
            ssl_socket.sendall(json.dumps({'header': 'login', 'username': 'user2', 'password': "2"}).encode())
            info = ssl_socket.recv(4096).decode()

            if info == "You login":
                print(info)
                # Set the event to signal that login was successful
                login_event.set()

                thread = threading.Thread(target=connect_waiting, args=(ssl_socket, local_ip, local_port,))
                thread.start()

                while True:
                    info = ''
                    if info == 'cr':
                        pass

                thread.join()


if __name__ == "__main__":
    main()
