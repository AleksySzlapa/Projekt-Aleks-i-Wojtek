import json
import secrets
import socket
import ssl
import threading
import time
from hashlib import sha256

from Crypto.Cipher import AES
from argon2 import PasswordHasher
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from sympy import randprime, primitive_root


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
    csr = generate_csr(private_key, "client.com")
    save_key_to_file_using_pem(private_key, 'client')
    # Connect to CA client
    with socket.create_connection((ca_host, ca_port)) as ca_socket:
        # Wrap the socket for SSL
        with ssl.wrap_socket(ca_socket, ssl_version=ssl.PROTOCOL_TLS) as ssl_ca_socket:
            # Send CSR
            ssl_ca_socket.sendall(csr.public_bytes(encoding=serialization.Encoding.PEM))
            # Receive signed certificate
            signed_cert_pem = ssl_ca_socket.recv(4096)
            ca_cert = ssl_ca_socket.recv(4096)
            with open(f"client.crt", "wb") as f:
                f.write(signed_cert_pem)
                f.close()
            with open(f"client_ca.crt", "wb") as f:
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


def connect_request(friend_username, username, server_socket):
    server_socket.sendall("cr".encode())
    server_socket.sendall(f"{friend_username}".encode())
    address = server_socket.recv(4096).decode()

    if address == 'offline':
        print('User is offline')
        return '0'
    else:

        address = address.split(":")
        friend_ip, friend_port = address[0], address[1]


        friend_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        friend_context.load_cert_chain(certfile="client.crt", keyfile="client.key")
        friend_context.load_verify_locations(cafile="client_ca.crt")
        friend_context.verify_mode = ssl.CERT_REQUIRED
        friend_context.check_hostname = False  # Disable hostname checking for server side

        with socket.create_connection((friend_ip, int(friend_port))) as friend_socket:
            with friend_context.wrap_socket(friend_socket) as ssl_friend_socket:
                ssl_friend_socket.sendall(username.encode())
                dec = ssl_friend_socket.recv(4096).decode()
                if dec == "n":
                    ssl_friend_socket.close()
                else:
                    p = randprime(10 ** 19, 10 ** 20)

                    g = primitive_root(p)

                    a = secrets.randbits(20)

                    ssl_friend_socket.sendall(json.dumps({'p': p, 'g': g}).encode())

                    B = ssl_friend_socket.recv(4096).decode()

                    s = int(B) ** a % p

                    A = g ** a % p
                    ssl_friend_socket.sendall(str(A).encode())

                    key = generate_AES_key(s)

                    def send_message(key, text):

                        ciphertext, tag, nonce = encrypt(key, text.encode())

                        ssl_friend_socket.sendall(ciphertext)
                        ssl_friend_socket.sendall(tag)
                        ssl_friend_socket.sendall(nonce)

                    def receive_message(key):
                        ciphertext = ssl_friend_socket.recv(4096)
                        tag = ssl_friend_socket.recv(4096)
                        nonce = ssl_friend_socket.recv(4096)

                        text = decrypt(key, ciphertext, tag, nonce)
                        return text

                    def handle_sending(key):
                        while True:
                            message = input(f"You: ")
                            send_message(key, message)

                    def handle_receiving(key):
                        while True:
                            message = receive_message(key)
                            print(f"Friend: {message.decode()}")

                    sending_thread = threading.Thread(target=handle_sending, args=(key,))
                    receiving_thread = threading.Thread(target=handle_receiving, args=(key,))

                    sending_thread.start()
                    receiving_thread.start()

                    sending_thread.join()
                    receiving_thread.join()


def main():
    ca_host = 'localhost'
    ca_port = 7070
    sign_csr(ca_host, ca_port)

    server_host = 'localhost'
    server_port = 6969
    server_name = "server.com"

    # Create SSL/TLS context for the client
    client_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    client_context.load_cert_chain(certfile="client.crt", keyfile="client.key")
    client_context.check_hostname = True
    client_context.verify_mode = ssl.CERT_REQUIRED
    client_context.load_verify_locations(cafile="client_ca.crt")

    with socket.create_connection((server_host, server_port)) as client_socket:
        local_ip, local_port = client_socket.getsockname()

        with client_context.wrap_socket(client_socket, server_hostname=server_name) as ssl_socket:
            ssl.match_hostname(ssl_socket.getpeercert(), server_name)
            ssl_socket.sendall(json.dumps({'header': 'login', 'username': 'user', 'password': "1"}).encode())
            print('sex')
            info = ssl_socket.recv(4096).decode()
            print(info)
            if info == "You login":
                print(info)
                while True:
                    info = input("Enter 'cr' to send connect request: ")
                    if info == 'cr':
                        connect_request('user2', 'user', ssl_socket)
                    else:
                        break



if __name__ == "__main__":
    main()
