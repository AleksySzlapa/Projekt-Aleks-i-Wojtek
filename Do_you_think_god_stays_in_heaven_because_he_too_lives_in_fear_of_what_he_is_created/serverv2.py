import json
import socket
import sqlite3
import ssl
import threading

import select
from argon2 import PasswordHasher
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

un = ""


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
    private_key = generate_private_key()
    csr = generate_csr(private_key, "server.com")
    save_key_to_file_using_pem(private_key, 'server')
    with socket.create_connection((ca_host, ca_port)) as ca_socket:
        with ssl.wrap_socket(ca_socket, ssl_version=ssl.PROTOCOL_TLS) as ssl_ca_socket:
            ssl_ca_socket.sendall(csr.public_bytes(encoding=serialization.Encoding.PEM))
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
    PORT = 6969
    ca_host = 'localhost'
    ca_port = 7070

    request_sign_csr(ca_host, ca_port)
    server_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    server_context.load_cert_chain(certfile="server.crt", keyfile="server.key")
    server_context.check_hostname = False
    server_context.verify_mode = ssl.CERT_REQUIRED
    server_context.load_verify_locations(cafile="server_ca.crt")

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)

    print(f"Server listening on {HOST}:{PORT}")

    ssl_server_socket = server_context.wrap_socket(server_socket, server_side=True)

    sockets_list = [ssl_server_socket]

    clients = {}
    user_sessions = {}

    def handle_client(client_socket):
        try:
            def verified_user(socket, username):
                while True:
                    print("us", user_sessions)
                    print("c", clients)
                    try:
                        option = socket.recv(4096).decode()
                        if not option:
                            break
                        elif option == 'cr':
                            friend_username = socket.recv(4096).decode()
                            if friend_username in user_sessions:
                                friend_socket = user_sessions[friend_username]
                                try:
                                    friend_socket.sendall(username.encode())
                                    ip_address, port = friend_socket.getpeername()
                                    socket.sendall(f"{ip_address}:{port}".encode())
                                except Exception as e:
                                    print(f"Error communicating with friend {friend_username}: {e}")
                                    socket.sendall(f"error".encode())
                                    break
                            else:
                                socket.sendall("offline".encode())
                        elif option == 'cc':

                            friend_username_cc = socket.recv(4096).decode()
                            print(friend_username_cc, list(user_sessions.keys()))
                            print(user_sessions)
                            if friend_username_cc in list(user_sessions.keys()):
                                friend_socket = user_sessions[friend_username_cc]
                                try:
                                    ip_address, port = friend_socket.getpeername()

                                    socket.sendall(f"{ip_address}".encode())
                                except Exception as e:
                                    print(f"Error getting peer name for friend {friend_username_cc}: {e}")
                                    socket.send("error".encode())
                                    break
                            else:
                                socket.sendall('w'.encode())
                    except Exception as e:
                        print(f'Error with  verified_user: {e}')
                        break

            def handle_login(data, socket, pass_data):
                global un
                try:
                    print("w", pass_data)
                    conn = sqlite3.connect('cool_database.db')
                    cur = conn.cursor()
                    cur.execute('SELECT username, password, id FROM users WHERE username = ?', (pass_data["username"],))

                    data1 = cur.fetchone()
                    if data1:
                        db_username, db_password, user_id = data1
                    else:
                        client_socket.sendall("x".encode())
                        handle_something(socket)
                        return
                    username, password = data["username"], data['password']
                    print("what", username, password)
                    print("www", db_username, db_password, user_id)
                    if db_username:
                        if db_username == username:
                            ph = PasswordHasher()
                            try:
                                if ph.verify(db_password, password):
                                    client_socket.sendall("You login".encode())
                                    user_sessions[username] = socket
                                    verified_user(socket, username)
                                    un = username
                            except Exception as e:
                                client_socket.sendall("x1".encode())
                                handle_something(socket)
                                print(f"Error with password: {e}")

                            finally:
                                cur.close()
                                conn.close()
                except Exception as e:
                    client_socket.sendall("x2".encode())
                    handle_something(socket)
                    print(f"Error with login: {e}")

            def handle_register(data, socket):
                try:
                    conn = sqlite3.connect('cool_database.db')
                    cur = conn.cursor()
                    cur.execute('SELECT username FROM users ')
                    usernames = cur.fetchall()
                    username, password = data["username"], data['password']
                    if username not in usernames:
                        ph = PasswordHasher()
                        cur.execute('INSERT INTO users (username, password) VALUES (?, ?)',
                                    (username, ph.hash(password)))
                        conn.commit()
                        socket.sendall("register success".encode())
                        handle_something(client_socket)
                    cur.close()
                    conn.close()
                except Exception as e:
                    print(f"Error with register: {e}")

            def handle_something(client_socket):
                request = client_socket.recv(4096)

                if not request:
                    return False
                print(request)
                pass_data = json.loads(request)
                print(pass_data)
                if pass_data['header'] == 'login':
                    print("login beg")
                    handle_login(pass_data, client_socket, pass_data)
                elif pass_data['header'] == 'register':
                    handle_register(pass_data, client_socket)

            try:
                handle_something(client_socket)
            except Exception as e:
                print(f"Error: {e}")
                return False
        except Exception as e:
            print(f"Error: {e}")

    def handle_client_thread(client_socket, client_address):
        print(f"Accepted new connection from {client_address}")
        sockets_list.append(client_socket)
        clients[client_socket] = client_address
        while handle_client(client_socket):
            pass
        sockets_list.remove(client_socket)
        if un != "":
            del user_sessions[un]
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
