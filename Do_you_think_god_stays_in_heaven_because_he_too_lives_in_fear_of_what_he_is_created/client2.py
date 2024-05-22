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
    """
    Generate a new RSA private key.
    """
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )


def generate_csr(private_key, common_name):
    """
    Generate a Certificate Signing Request (CSR) using the provided private key and common name.
    """
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
    """
    Save the private key to a file in PEM format.
    """
    with open(f"{filename}.key", "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
        f.close()


def save_cert_to_file_using_pem(cert, filename):
    """
    Save the certificate to a file in PEM format.
    """
    with open(f"{filename}.crt", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
        f.close()


def sign_csr(ca_host, ca_port):
    """
    Sign the CSR by connecting to the Certificate Authority (CA) server.
    """
    private_key = generate_private_key()
    csr = generate_csr(private_key, "client.com")
    save_key_to_file_using_pem(private_key, 'client')

    with socket.create_connection((ca_host, ca_port)) as ca_socket:
        with ssl.wrap_socket(ca_socket, ssl_version=ssl.PROTOCOL_TLS) as ssl_ca_socket:
            ssl_ca_socket.sendall(csr.public_bytes(encoding=serialization.Encoding.PEM))
            signed_cert_pem = ssl_ca_socket.recv(4096)
            ca_cert = ssl_ca_socket.recv(4096)
            with open(f"client.crt", "wb") as f:
                f.write(signed_cert_pem)
                f.close()
            with open(f"client_ca.crt", "wb") as f:
                f.write(ca_cert)
                f.close()


def generate_AES_key(s):
    """
    Generate an AES key from the shared secret.
    """
    dh_s_bytes = s.to_bytes((s.bit_length() + 7) // 8, 'big')
    s_sha256 = sha256(dh_s_bytes).digest()
    AES_key = s_sha256[:16]
    return AES_key


def encrypt(key, plaintext):
    """
    Encrypt the plaintext using AES encryption.
    """
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return ciphertext, tag, nonce


def decrypt(key, ciphertext, tag, nonce):
    """
    Decrypt the ciphertext using AES decryption.
    """
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    try:
        cipher.verify(tag)
        return plaintext
    except ValueError:
        print("Key incorrect or message corrupted")


def connect_waiting(ip, port):
    """
    Wait for an incoming connection and handle Diffie-Hellman key exchange for secure communication.
    """
    try:
        print("waiting for connection")
        friend_waiting_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        friend_waiting_context.load_cert_chain(certfile="client2.crt", keyfile="client2.key")
        friend_waiting_context.load_verify_locations(cafile="client2_ca.crt")
        friend_waiting_context.verify_mode = ssl.CERT_REQUIRED
        friend_waiting_context.check_hostname = False

        friend_waiting_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        friend_waiting_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        friend_waiting_socket.bind((ip, int(port)))
        friend_waiting_socket.listen(5)

        with friend_waiting_socket:
            with friend_waiting_context.wrap_socket(friend_waiting_socket, server_side=True) as ssl_friend_waiting_socket:
                friend_socket, friend_address = ssl_friend_waiting_socket.accept()
                with friend_socket:
                    friend_username = friend_socket.recv(4096).decode()
                    print(f"incoming calling from {friend_username}")
                    dec = input("do you accept? y/n: ")
                    if dec == "n":
                        friend_socket.sendall("n".encode())
                        friend_socket.close()
                        exit()
                    else:
                        friend_socket.sendall("y".encode())
                        data = friend_socket.recv(4096).decode()
                        data = json.loads(data)
                        p = data['p']
                        g = data['g']
                        b = secrets.randbits(8)
                        B = g ** b % p
                        friend_socket.sendall(str(B).encode())
                        A = friend_socket.recv(4096).decode()
                        s = int(A) ** b % p
                        key = generate_AES_key(s)

                        def send_message(key, text):
                            """
                            Encrypt and send a message to the friend.
                            """
                            ciphertext, tag, nonce = encrypt(key, text.encode())
                            friend_socket.sendall(ciphertext)
                            friend_socket.sendall(tag)
                            friend_socket.sendall(nonce)

                        def receive_message(key):
                            """
                            Receive and decrypt a message from the friend.
                            """
                            ciphertext = friend_socket.recv(4096)
                            tag = friend_socket.recv(4096)
                            nonce = friend_socket.recv(4096)
                            text = decrypt(key, ciphertext, tag, nonce)
                            return text

                        def handle_sending(key):
                            """
                            Handle the sending of messages in a loop.
                            """
                            while True:
                                message = input(f"You: ")
                                if message == "":
                                    continue
                                send_message(key, message)

                        def handle_receiving(key):
                            """
                            Handle the receiving of messages in a loop.
                            """
                            while True:
                                message = receive_message(key)
                                print(f"Friend: {message.decode()}")

                        # Start threads for sending and receiving messages
                        sending_thread = threading.Thread(target=handle_sending, args=(key,))
                        receiving_thread = threading.Thread(target=handle_receiving, args=(key,))

                        sending_thread.start()
                        receiving_thread.start()

                        sending_thread.join()
                        receiving_thread.join()
    except Exception as e:
        print(f"Error in connect_waiting: {e}")


def connect_request(friend_username, username, server_socket):
    """
    Send a connection request to a friend and handle Diffie-Hellman key exchange for secure communication.
    """
    server_socket.sendall("cr".encode())
    server_socket.sendall(f"{friend_username}".encode())
    address = server_socket.recv(4096).decode()

    if address == 'offline':
        print('User is offline or not exist')
        return '0'
    else:
        address = address.split(":")
        friend_ip, friend_port = address[0], address[1]

        friend_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        friend_context.load_cert_chain(certfile="client.crt", keyfile="client.key")
        friend_context.load_verify_locations(cafile="client_ca.crt")
        friend_context.verify_mode = ssl.CERT_REQUIRED
        friend_context.check_hostname = False

        with socket.create_connection((friend_ip, int(friend_port))) as friend_socket:
            with friend_context.wrap_socket(friend_socket) as ssl_friend_socket:
                ssl_friend_socket.sendall(username.encode())
                print(f"waiting for {friend_username} answer")
                dec = ssl_friend_socket.recv(4096).decode()

                if dec == "n":
                    print(f"{friend_username} decline")
                    ssl_friend_socket.close()
                    exit()
                else:
                    print(f"{friend_username} accept")
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
                        """
                        Encrypt and send a message to the friend.
                        """
                        ciphertext, tag, nonce = encrypt(key, text.encode())
                        ssl_friend_socket.sendall(ciphertext)
                        ssl_friend_socket.sendall(tag)
                        ssl_friend_socket.sendall(nonce)

                    def receive_message(key):
                        """
                        Receive and decrypt a message from the friend.
                        """
                        ciphertext = ssl_friend_socket.recv(4096)
                        tag = ssl_friend_socket.recv(4096)
                        nonce = ssl_friend_socket.recv(4096)
                        text = decrypt(key, ciphertext, tag, nonce)
                        return text

                    def handle_sending(key):
                        """
                        Handle the sending of messages in a loop.
                        """
                        while True:
                            message = input(f"You: ")
                            if message == "":
                                continue
                            send_message(key, message)

                    def handle_receiving(key):
                        """
                        Handle the receiving of messages in a loop.
                        """
                        while True:
                            message = receive_message(key)
                            print(f"Friend: {message.decode()}")

                    # Start threads for sending and receiving messages
                    sending_thread = threading.Thread(target=handle_sending, args=(key,))
                    receiving_thread = threading.Thread(target=handle_receiving, args=(key,))

                    sending_thread.start()
                    receiving_thread.start()

                    sending_thread.join()
                    receiving_thread.join()


def login(ssl_socket):
    """
    Handle the login or registration process for the user.
    """
    option = input("For login type l or r for register: ")
    if option == "l":
        username = input("username: ")
        password = input("password: ")
        ssl_socket.sendall(json.dumps({'header': 'login', 'username': username, 'password': password}).encode())
    elif option == "r":
        username = input("username: ")
        password = input("password: ")
        password_again = input("password again: ")
        if password == password_again:
            ssl_socket.sendall(json.dumps({'header': 'register', 'username': username, 'password': password}).encode())
        else:
            print("Incorrect password")
            login(ssl_socket)
    else:
        login(ssl_socket)


def main():
    """
    Main function to initiate the client, handle login, and manage connections.
    """
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
            info = ''
            while info != "You login":
                login(ssl_socket)
                info = ssl_socket.recv(4096).decode()
                if info == "You login":
                    while True:
                        info = input("Enter 'cr' to send connect request or enter 'cw' to connect waiting: ")
                        if info == 'cr':
                            friend = input("Write friend username: ")
                            if friend == "":
                                continue
                            connect_request(friend, 'user', ssl_socket)
                        elif info == "cw":
                            connect_waiting(local_ip, local_port)
                        else:
                            break


if __name__ == "__main__":
    main()
