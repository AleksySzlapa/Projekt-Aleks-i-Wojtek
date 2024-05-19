import json
import socket
import sqlite3
import ssl
import threading
import re

import select
from argon2 import PasswordHasher
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


def request_sign_csr(ca_host, ca_port):
    # Generate private key and CSR
    private_key = generate_private_key()
    csr = generate_csr(private_key, "server.com")
    save_key_to_file_using_pem(private_key, 'server')
    # Connect to CA server
    with socket.create_connection((ca_host, ca_port)) as ca_socket:
        # Wrap the socket for SSL
        with ssl.wrap_socket(ca_socket, ssl_version=ssl.PROTOCOL_TLS) as ssl_ca_socket:
            # Send CSR
            ssl_ca_socket.sendall(csr.public_bytes(encoding=serialization.Encoding.PEM))
            # Receive signed certificate
            signed_cert_pem = ssl_ca_socket.recv(4096)
            ca_cert = ssl_ca_socket.recv(4096)
            with open(f"server.crt", "wb") as f:
                f.write(signed_cert_pem)
                f.close()
            with open(f"server_ca.crt", "wb") as f:
                f.write(ca_cert)
                f.close()


def main():
    HOST = 'localhost'
    PORT = 7776
    ca_host = 'localhost'
    ca_port = 8889

    request_sign_csr(ca_host, ca_port)
    #socket.setdefaulttimeout(5)
    # Set up the SSL context
    server_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    server_context.load_cert_chain(certfile="server.crt", keyfile="server.key")
    server_context.check_hostname = False
    server_context.verify_mode = ssl.CERT_REQUIRED
    server_context.load_verify_locations(cafile="server_ca.crt")

    # Create a TCP/IP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)

    print(f"Server listening on {HOST}:{PORT}")

    # Wrap the server socket with SSL
    ssl_server_socket = server_context.wrap_socket(server_socket, server_side=True)

    # List of sockets to monitor for incoming connections
    sockets_list = [ssl_server_socket]

    # A dictionary to store client addresses and sockets
    clients = {}
    # A dictionary to store user sessions
    user_sessions = {}

    def handle_client(client_socket):
        try:
            request = client_socket.recv(4096)
            if not request:
                return False
            pass_data = json.loads(request)
            conn = sqlite3.connect('cool_database.db')
            cur = conn.cursor()
            print(pass_data)

            if pass_data['header'] == 'login':
                cur.execute('SELECT password, id FROM users WHERE username = ?', (pass_data["username"],))
                user = cur.fetchone()
                user_id = pass_data["username"]
                if user:
                    id = user[1]
                    password = user[0]
                    ph = PasswordHasher()
                    if ph.verify(password, pass_data["password"]):
                        client_socket.sendall("You login".encode())
                        cur.execute('UPDATE users SET status = ? WHERE id = ?', (1, id))
                        conn.commit()
                        user_sessions[user_id] = client_socket

                    while True:
                        info = client_socket.recv(4096).decode()
                        if not info:
                            break
                        elif info == 'check':
                            check_ip = client_socket.recv(4096).decode()
                            print('check_ip', check_ip)
                            if check_ip in user_sessions:
                                check_ip_socket = user_sessions[check_ip]
                                print(check_ip_socket)
                                ip_address, port = check_ip_socket.getpeername()
                                port = str(port)
                                print((ip_address + ':' + port))
                                client_socket.sendall((ip_address + ':' + port).encode())
                            else:
                                client_socket.sendall('run'.encode())
                        elif info == "friends":
                            cur.execute('SELECT user_1, user_2 FROM friends WHERE user_1 = ? OR user_2 = ?', (id, id))
                            friends_list_data = cur.fetchall()
                            friends_list = {friend[1] if friend[0] == id else friend[0] for friend in friends_list_data}
                            friends_list_over_haeven = []
                            for friend in friends_list:
                                cur.execute('SELECT username, id, status FROM users WHERE id = ?', (friend,))
                                friends_list_over_haeven.append(cur.fetchone())
                            client_socket.sendall(json.dumps(friends_list_over_haeven).encode())
                            cur.execute('SELECT user_1, user_2 FROM friends_requests WHERE user_2 = ?', (id,))
                            friends_requests_list = cur.fetchall()
                            friends_requests_list_over_haeven = []
                            for friend_request in friends_requests_list:
                                cur.execute('SELECT username, id FROM users WHERE id = ?', (friend_request[0],))
                                friends_requests_list_over_haeven.append(cur.fetchone())
                            client_socket.sendall(json.dumps(friends_requests_list_over_haeven).encode())

                        elif info == "add_friend":
                            new_friend_username = client_socket.recv(4096).decode()
                            cur.execute('SELECT id FROM users WHERE username = ?', (new_friend_username,))
                            friend_id = cur.fetchone()[0]
                            cur.execute('SELECT * FROM friends_requests WHERE (user_1 = ? AND user_2 = ?)',
                                        (id, friend_id))
                            if not cur.fetchall():
                                cur.execute('INSERT INTO friends_requests (user_1, user_2) VALUES (?, ?)',
                                            (id, friend_id))
                                conn.commit()

                        elif info == 'acore':
                            data = json.loads(client_socket.recv(4096))
                            cur.execute('SELECT id FROM users WHERE username = ?', (data[0],))
                            new_friend_id = cur.fetchone()[0]
                            if data[1] == 0:
                                cur.execute(
                                    'UPDATE friends_requests SET isWaiting = ?, isAccept = ? WHERE (user_1 = ? AND user_2 = ?) AND isWaiting = 1',
                                    (0, 0, id, new_friend_id)
                                )
                                conn.commit()
                            elif data[1] == 1:
                                cur.execute(
                                    'UPDATE friends_requests SET isWaiting = ?, isAccept = ? WHERE (user_1 = ? AND user_2 = ?) AND isWaiting = 1',
                                    (0, 1, id, new_friend_id)
                                )
                                cur.execute('INSERT INTO friends (user_1, user_2) VALUES (?, ?)', (id, new_friend_id))
                                conn.commit()

                        elif info == "connect_request":
                            print('req', user_sessions)
                            target_id = client_socket.recv(4096).decode()
                            if target_id in user_sessions:
                                print('ezzzzzzz')
                                target_socket = user_sessions[target_id]
                                target_socket.sendall(f'calling {user_id}'.encode())
                                print('ts',target_socket)

                                ip_address, port = target_socket.getpeername()
                                print(ip_address, port)
                                client_socket.sendall(f"{ip_address}:{port}:{target_id}".encode())
                                print('done')
                            else:
                                client_socket.sendall("User not online".encode())

                        elif info.startswith("connect_accept"):
                            print('acc', user_sessions)
                            target_id = info.split(" ")[1]
                            if target_id in user_sessions:
                                target_socket = user_sessions[target_id]
                                target_socket.sendall(f"connect_accept from {id}".encode())
                                client_socket.sendall(f"connect_accept to {target_id}".encode())

                        elif info == 'END':
                            break
                    # Remove user session upon disconnection
                    del user_sessions[user_id]
                    cur.close()
                    conn.close()
                    client_socket.sendall("Disconnected".encode())
                else:
                    client_socket.sendall("login fail".encode())

            elif pass_data['header'] == 'register':
                # Simulate a user registration (for demonstration purposes)
                client_socket.sendall("register".encode())

            return True

        except Exception as e:
            print(f"Error: {e}")
            return False

    def handle_client_thread(client_socket, client_address):
        print(f"Accepted new connection from {client_address}")
        sockets_list.append(client_socket)
        clients[client_socket] = client_address
        while handle_client(client_socket):
            pass
        sockets_list.remove(client_socket)
        del clients[client_socket]
        client_socket.close()
        print(f"Closed connection from {client_address}")

    while True:
        read_sockets, _, exception_sockets = select.select(sockets_list, [], sockets_list)
        for notified_socket in read_sockets:
            if notified_socket == ssl_server_socket:
                try:
                    client_socket, client_address = ssl_server_socket.accept()
                    client_thread = threading.Thread(target=handle_client_thread, args=(client_socket, client_address))
                    client_thread.start()
                except ssl.SSLError as e:
                    print(f"SSL error: {e}")

        for notified_socket in exception_sockets:
            sockets_list.remove(notified_socket)
            if notified_socket in clients:
                del clients[notified_socket]
            notified_socket.close()


if __name__ == "__main__":
    main()
