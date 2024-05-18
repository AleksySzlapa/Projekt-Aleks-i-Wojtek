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


def login(username, password):
    ph = PasswordHasher()
    data = {"header": "login", 'username': username, 'password': password}
    # hashed_password = ph.hash(password)
    data = json.dumps(data, indent=4)
    return data


def register(username, password, password_again):
    ph = PasswordHasher()
    data = {"header": "register"}
    # hashed_password = ph.hash(password)
    if password != password_again:
        return None
    data['username'] = username
    data['password'] = password
    data = json.dumps(data, indent=4)
    return data


def Sisyphus(option, ss_socket, username, password, password_again):
    if option == "l":
        login_pass = login(username, password)
        print(login_pass)
        ss_socket.sendall(login_pass.encode())
    else:
        while True:
            register_pass = register(username, password, password_again)
            if register_pass is not None:
                ss_socket.sendall(register_pass.encode())
                break
        print(register_pass)


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


def main():
    ca_host = 'localhost'
    ca_port = 8889

    sign_csr(ca_host, ca_port)
    server_host = 'localhost'
    server_port = 7776
    server_name = "server.com"

    # Utwórz kontekst SSL/TLS dla klienta
    client2_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    client2_context.load_cert_chain(certfile="client2.crt", keyfile="client2.key")

    # Wymaga weryfikacji certyfikatu serwera podpisanego przez zaufane CA
    client2_context.check_hostname = True
    client2_context.verify_mode = ssl.CERT_REQUIRED

    # client2_context.load_verify_locations(cafile="ca.crt")
    client2_context.load_verify_locations(cafile="client2_ca.crt")
    # Utwórz połączenie TCP i nawiaż połączenie SSL/TLS z serwerem
    with socket.create_connection((server_host, server_port)) as client2_socket:
        local_ip, local_port = client2_socket.getsockname()
        with client2_context.wrap_socket(client2_socket, server_hostname=server_name) as ssl_socket:
            ssl.match_hostname(ssl_socket.getpeercert(), server_name)
            option = 'l'  # input("select l or r: ")

            Sisyphus(option, ssl_socket, "2s", "2", "2")
            info = ssl_socket.recv(4096).decode()
            print(info)
            if info == "You login":
                # Funkcja do obsługi komunikacji ze zdalnym serwerem
                def communicate_with_friend(ssl_socket):
                    server_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                    server_context.load_cert_chain(certfile="client.crt", keyfile="client.key")
                    server_context.load_verify_locations(cafile="client_ca.crt")
                    server_context.verify_mode = ssl.CERT_REQUIRED
                    server_context.check_hostname = False  # Disable hostname checking for server side

                    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    server_socket.bind((local_ip, local_port))
                    server_socket.listen(5)

                    with server_socket:
                        with server_context.wrap_socket(server_socket, server_side=True) as ssl_server_socket:
                            client_socket, client_address = ssl_server_socket.accept()
                            with client_socket:
                                print('to to')
                                data = client_socket.recv(4096).decode().split(" ")
                                dec = input(f"{data[1]} is calling y/n:")
                                if dec == 'n':
                                    client_socket.sendall('conn dec'.encode())
                                else:
                                    client_socket.sendall('conn act'.encode())
                                    print('conn act')
                                    data = client_socket.recv(4096).decode()
                                    print('data', data)
                                    data = json.loads(data)
                                    p = data['p']
                                    g = data['g']
                                    b = secrets.randbits(8)
                                    print('START B')
                                    B = g ** b % p
                                    print('END B')
                                    client_socket.sendall(str(B).encode())
                                    A = client_socket.recv(4096).decode()
                                    s = int(A) ** b % p
                                    print('s', s)
                                    key = generate_AES_key(s)

                                    def send_message(key, text):

                                        ciphertext, tag, nonce = encrypt(key, text.encode())

                                        client_socket.sendall(ciphertext)
                                        client_socket.sendall(tag)
                                        client_socket.sendall(nonce)

                                    def receive_message(key):
                                        ciphertext = client_socket.recv(4096)
                                        tag = client_socket.recv(4096)
                                        nonce = client_socket.recv(4096)

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

                # Rozpocznij nasłuchiwanie w oddzielnym wątku
                listener_thread = threading.Thread(target=communicate_with_friend, args=(ssl_socket,))
                listener_thread.start()
                while True:

                    # Pozwól użytkownikowi na interakcję
                    info = input('sex')
                    # Obsłuż różne komendy użytkownika
                    if info == 'END':
                        ssl_socket.sendall('END'.encode())
                        ssl_socket.close()
                        break
                    elif info.startswith('connect_request'):

                        # Obsługa połączeń

                        ssl_socket.sendall(info.encode())
                    elif info == 'f':
                        ssl_socket.sendall("friends".encode())
                        friends_username_list = ssl_socket.recv(4096).decode()
                        friends_requests_username_list = ssl_socket.recv(4096).decode()
                        print('friends', friends_username_list)
                        print('requests', friends_requests_username_list)
                    elif info == 'ad':
                        ssl_socket.sendall("add_friend".encode())
                        ssl_socket.sendall('4s'.encode())
                    elif info == 'aco':
                        ssl_socket.sendall('acore'.encode())
                        data = ['4s', 0]
                        data = json.dumps(data)
                        ssl_socket.sendall(data.encode())
                    elif info == 'cr':
                        print('one')
                        ssl_socket.sendall("connect_request".encode())
                        ssl_socket.sendall("1s".encode())
                        print('two')
                        address = ssl_socket.recv(4096).decode()
                        print('add', address)
                        address = address.split(":")
                        time.sleep(3)
                        friend_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
                        friend_context.load_cert_chain(certfile="client.crt", keyfile="client.key")
                        friend_context.load_verify_locations(cafile="client_ca.crt")
                        friend_context.verify_mode = ssl.CERT_REQUIRED
                        friend_context.check_hostname = False  # Disable hostname checking for server side
                        with socket.create_connection((address[0], int(address[1]))) as friend_socket:
                            with friend_context.wrap_socket(friend_socket) as ssl_friend_socket:
                                # ssl.match_hostname(ssl_socket.getpeercert(), address[2])
                                ssl_friend_socket.sendall('call 2s'.encode())
                                isAccpet = ssl_friend_socket.recv(4096).decode()
                                if isAccpet == 'conn dec':
                                    ssl_friend_socket.close()
                                else:
                                    p = randprime(10 ** 19, 10 ** 20)

                                    g = primitive_root(p)

                                    a = secrets.randbits(8)

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
                    elif info == 'END':
                        ssl_socket.sendall('END'.encode())
                        ssl_socket.close()

    # Po wyjściu z pętli głównej zakończ wątek nasłuchujący

    listener_thread.join()


if __name__ == "__main__":
    main()
