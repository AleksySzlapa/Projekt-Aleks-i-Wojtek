import socket
import ssl


def connect_request(friend_username, username, server_socket):
    server_socket.sendall("cr".encode())
    server_socket.sendall(f"{friend_username}".encode())
    address = server_socket.recv(4096).decode().split(":")
    if address == 'offline':
        print('chuj ci w dupe')
    else:
        firend_ip, friend_port = address[0], address[1]
        friend_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        friend_context.load_cert_chain(certfile="client.crt", keyfile="client.key")
        friend_context.load_verify_locations(cafile="client_ca.crt")
        friend_context.verify_mode = ssl.CERT_REQUIRED
        friend_context.check_hostname = False  # Disable hostname checking for server side
        with socket.create_connection((firend_ip, int(friend_port))) as friend_socket:
            with friend_context.wrap_socket(friend_socket) as ssl_friend_socket:
                ssl_friend_socket.sendall(username.encode())
                print(ssl_friend_socket.recv(4096).decode())
                ssl_friend_socket.sendall('pong'.encode())

def connect_waiting(server_socket, ip, port):
    friend_waiting_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    friend_waiting_context.load_cert_chain(certfile="client.crt", keyfile="client.key")
    friend_waiting_context.load_verify_locations(cafile="client_ca.crt")
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
                friend_username = friend_socket.recv(4096)
                friend_ip, port = friend_socket.getpeername()
                server_socket.sendall('cc'.encode())
                server_socket.sendall(f'{friend_username}'.encode())
                real_firend_ip = server_socket.recv(4096)
                if real_firend_ip == 'w':
                    friend_socket.close()
                else:
                    if friend_ip != real_firend_ip:
                        friend_socket.close()
                    else:
                        friend_socket.sendall('ping'.encode())
                        print(friend_socket.recv(4096).decode())
