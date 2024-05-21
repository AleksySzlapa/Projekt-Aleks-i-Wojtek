import sys
from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QLineEdit, QPushButton, QDesktopWidget, \
    QLayout, QHBoxLayout, QLabel, QMessageBox
from PyQt5.QtCore import Qt, pyqtSignal, QThread
import json
import socket
import ssl
from client2 import *



class NetworkThread(QThread):
    login_success_signal = pyqtSignal()
    register_success_signal = pyqtSignal()

    def __init__(self, mode, ssl_socket, username, password):
        super().__init__()
        self.mode = mode
        self.ssl_socket = ssl_socket
        self.username = username
        self.password = password

    def run(self):
        data = {"header": f"{self.mode}", 'username': self.username, 'password': self.password}
        data = json.dumps(data, indent=4)
        print(f"Sending data to server: {data}")  # Debug statement
        self.ssl_socket.sendall(data.encode())
        info = self.ssl_socket.recv(4096)
        print(f"Received data from server: {info}")  # Debug statement
        if info == b'You login':
            self.login_success_signal.emit()
            global my_username
            my_username = self.username
        elif info == b'register success':
            self.register_success_signal.emit()

class Call_Await_Thread(QThread):
    call_requested = pyqtSignal()

    def __init__(self):
        super().__init__()

    def run(self):
        print('ipw', local_ip, local_port)
        try:

            friend_waiting_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            friend_waiting_context.load_cert_chain(certfile="client2.crt", keyfile="client2.key")
            friend_waiting_context.load_verify_locations(cafile="client2_ca.crt")
            friend_waiting_context.verify_mode = ssl.CERT_REQUIRED
            friend_waiting_context.check_hostname = False

            friend_waiting_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            friend_waiting_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            friend_waiting_socket.bind((local_ip, int(local_port)))
            print('Bound to IP', local_ip, 'Port', local_port)
            friend_waiting_socket.listen(5)

            with friend_waiting_socket:
                with friend_waiting_context.wrap_socket(friend_waiting_socket,
                                                        server_side=True) as ssl_friend_waiting_socket:
                    friend_socket, friend_address = ssl_friend_waiting_socket.accept()
                    with friend_socket:
                        firend_username = friend_socket.recv(4096)

                        def show_custom_dialog():
                            print('sex',firend_username)

                            msg_box = QMessageBox()
                            msg_box.setWindowTitle("Connection request")
                            msg_box.setText(f"Do you want to accept a connection from {firend_username}?")
                            msg_box.setStandardButtons(QMessageBox.Yes | QMessageBox.No)

                            # Customize the button texts
                            accept_button = msg_box.button(QMessageBox.Yes)
                            accept_button.setText("Accept")

                            decline_button = msg_box.button(QMessageBox.No)
                            decline_button.setText("Decline")
                            response = msg_box.exec_()
                            if response == QMessageBox.Yes:
                                return "yes"
                            elif response == QMessageBox.No:
                                return "no"
                        print(firend_username)
                        test = show_custom_dialog()
                        print(test)
                        dec = test
                        if dec == "no":
                            friend_socket.sendall("n".encode())
                            friend_socket.close()
                        else:
                            friend_socket.sendall("y".encode())

                            print('dzala')
                            data = friend_socket.recv(4096).decode()
                            print('data', data)
                            data = json.loads(data)
                            p = data['p']
                            g = data['g']
                            b = secrets.randbits(8)
                            print('START B')
                            B = g ** b % p
                            print('END B')
                            print(B)
                            friend_socket.sendall(str(B).encode())
                            A = friend_socket.recv(4096).decode()
                            s = int(A) ** b % p
                            print('s', s)
                            key = generate_AES_key(s)

                            def send_message(key, text):

                                ciphertext, tag, nonce = encrypt(key, text.encode())

                                friend_socket.sendall(ciphertext)
                                friend_socket.sendall(tag)
                                friend_socket.sendall(nonce)

                            def receive_message(key):
                                ciphertext = friend_socket.recv(4096)
                                tag = friend_socket.recv(4096)
                                nonce = friend_socket.recv(4096)

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
        except Exception as e:
            print(f"Error in connect_waiting: {e}")
        data = {"header": f"{self.mode}", 'username': self.username, 'password': self.password}
        data = json.dumps(data, indent=4)
        print(f"Sending data to server: {data}")  # Debug statement
        self.ssl_socket.sendall(data.encode())
        info = self.ssl_socket.recv(4096)
        print(f"Received data from server: {info}")  # Debug statement
        if info == b'You login':
            self.login_success_signal.emit()
            global my_username
            my_username = self.username
        elif info == b'register success':
            self.register_success_signal.emit()
def connect_request(friend_username, username, server_socket):
    print("test")
    server_socket.sendall("cr".encode())
    server_socket.sendall(f"{friend_username}".encode())
    address = server_socket.recv(4096).decode()
    print(address)
    if address == 'offline':
        print('User is offline')
        return '0'
    else:

        address = address.split(":")
        friend_ip, friend_port = address[0], address[1]


        friend_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        friend_context.load_cert_chain(certfile="client2.crt", keyfile="client2.key")
        friend_context.load_verify_locations(cafile="client2_ca.crt")
        friend_context.verify_mode = ssl.CERT_REQUIRED
        friend_context.check_hostname = False  # Disable hostname checking for server side

        with socket.create_connection((friend_ip, int(friend_port))) as friend_socket:
            with friend_context.wrap_socket(friend_socket) as ssl_friend_socket:
                ssl_friend_socket.sendall(username.encode())
                decision = ssl_friend_socket.recv(4096).decode()
                if decision == "n":
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

                    # TODO tutaj
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

class LoginWindow(QMainWindow):
    def __init__(self, ssl_socket):
        super().__init__()
        self.ssl_socket = ssl_socket
        self.network_thread = None  # Initialize network thread to None
        self.setWindowTitle('Login')
        self.width = 500
        self.height = 150
        self.setFixedSize(self.width, self.height)
        screen = QDesktopWidget().availableGeometry().center()
        x = screen.x() - self.width // 2
        y = screen.y() - self.height // 2
        self.setGeometry(x, y, self.width, self.height)

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        layout = QVBoxLayout()

        self.central_widget.setLayout(layout)
        self.central_widget.layout().setContentsMargins(0, 0, 0, 0)

        self.load_login()

    def reset_widget(self, widget):
        if isinstance(widget, QWidget):
            layout = widget.layout()
            if layout is not None:
                while layout.count():
                    item = layout.takeAt(0)
                    widget = item.widget()
                    if widget is not None:
                        widget.deleteLater()
                    else:
                        widget.reset_location(item.layout())

                # Delete the layout
                del layout
        elif isinstance(widget, QLayout):
            while widget.count():
                item = widget.takeAt(0)
                widget.reset_location(item.widget())

    def load_login(self):
        self.setWindowTitle('Login')
        self.reset_widget(self.central_widget)
        self.login_input = QLineEdit()
        self.login_input.setPlaceholderText("Login")

        self.pass_input = QLineEdit()
        self.pass_input.setPlaceholderText("Password")
        self.pass_input.setEchoMode(QLineEdit.Password)

        login_button = QPushButton("Login")
        login_button.clicked.connect(self.login)

        register_button = QPushButton("Register")
        register_button.clicked.connect(self.load_register)

        layout = self.central_widget.layout()
        layout.addWidget(self.login_input)
        layout.addWidget(self.pass_input)
        layout.addWidget(login_button)
        layout.addWidget(register_button)
        layout.setAlignment(Qt.AlignCenter)

    def load_register(self):
        self.setWindowTitle('Register')
        self.reset_widget(self.central_widget)
        self.login_input_r = QLineEdit()
        self.login_input_r.setPlaceholderText("New Login")

        self.pass_input_r = QLineEdit()
        self.pass_input_r.setPlaceholderText("Password")
        self.pass_input_r.setEchoMode(QLineEdit.Password)

        register_button = QPushButton("Register")
        register_button.clicked.connect(self.register)

        login_button = QPushButton("Login")
        login_button.clicked.connect(self.load_login)

        layout = self.central_widget.layout()
        layout.addWidget(self.login_input_r)
        layout.addWidget(self.pass_input_r)
        layout.addWidget(register_button)
        layout.addWidget(login_button)
        layout.setAlignment(Qt.AlignCenter)

    def login(self):
        username = self.login_input.text()
        password = self.pass_input.text()
        print(f"Logging in with username: {username} and password: {password}")  # Debug statement
        self.start_network_thread("login", username, password)

    def register(self):
        username = self.login_input_r.text()
        password = self.pass_input_r.text()
        if username != "" and password != "":
            print(f"Registering with username: {username} and password: {password}")  # Debug statement
            self.start_network_thread("register", username, password)

    def start_network_thread(self, mode, username, password):
        if self.network_thread and self.network_thread.isRunning():
            self.network_thread.quit()
            self.network_thread.wait()
        self.network_thread = NetworkThread(mode, self.ssl_socket, username, password)
        if mode == "login":
            self.network_thread.login_success_signal.connect(self.on_login_success)
        elif mode == "register":
            self.network_thread.register_success_signal.connect(self.on_register_success)
        self.network_thread.start()

    def on_login_success(self):
        print("Login successful!")  # Debug statement
        self.close()
        temp = Call_Await_Thread()
        temp.run()
        temp.exit()
        # self.main_window = MainWindow()
        # self.main_window.show()


    def on_register_success(self):
        print("Registration successful!")  # Debug statement
        self.load_login()

class Call_Window(QMainWindow):
    def __init__(self, called_user, calling_user):
        super().__init__()
        self.called_user = called_user
        self.calling_user = calling_user
        self.ssl_socket = ssl_socket
        self.setWindowTitle('Main Window')
        self.width = 700
        self.height = 100
        self.setFixedSize(self.width, self.height)
        screen = QDesktopWidget().availableGeometry().center()
        x = screen.x() - self.width // 2
        y = screen.y() - self.height // 2
        self.setGeometry(x, y, self.width, self.height)

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        layout = QHBoxLayout()

        self.central_widget.setLayout(layout)
        self.central_widget.layout().setContentsMargins(0, 0, 0, 0)
        self.load_awaiting()

    def load_awaiting(self):
        self.central_widget = QLabel("awaiting")
        connect_request(self.called_user, self.calling_user, self.ssl_socket)
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.ssl_socket = ssl_socket
        self.setWindowTitle('Main Window')
        self.width = 700
        self.height = 100
        self.setFixedSize(self.width, self.height)
        screen = QDesktopWidget().availableGeometry().center()
        x = screen.x() - self.width // 2
        y = screen.y() - self.height // 2
        self.setGeometry(x, y, self.width, self.height)

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        layout = QHBoxLayout()

        self.central_widget.setLayout(layout)
        self.central_widget.layout().setContentsMargins(0, 0, 0, 0)
        self.load_call_request_screen()

    def load_call_request_screen(self):
        self.entered_name = QLineEdit()
        self.entered_name.setPlaceholderText("Some other users name")

        request_button = QPushButton("Request_connection")
        request_button.clicked.connect(self.on_user_entered)

        self.central_widget.layout().addWidget(self.entered_name)
        self.central_widget.layout().addWidget(request_button)
        print(client_socket)

    def on_user_entered(self):
        pass
        # entered_name = self.entered_name.text()
        # call_window = Call_Window(entered_name, my_username)
        # call_window.show()




if __name__ == '__main__':
    # SSL/TLS setup
    server_host = 'localhost'
    server_port = 7776
    server_name = "server.com"
    ca_host = 'localhost'
    ca_port = 8889
    #sign_csr(ca_host, ca_port)
    client_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    client_context.load_cert_chain(certfile="client2.crt", keyfile="client2.key")
    client_context.check_hostname = True
    client_context.verify_mode = ssl.CERT_REQUIRED
    client_context.load_verify_locations(cafile="client2_ca.crt")


    with socket.create_connection((server_host, server_port)) as client_socket:
        local_ip, local_port = client_socket.getsockname()
        with client_context.wrap_socket(client_socket, server_hostname=server_name) as ssl_socket:
            app = QApplication(sys.argv)
            login_window = LoginWindow(ssl_socket)
            login_window.show()
            sys.exit(app.exec_())
