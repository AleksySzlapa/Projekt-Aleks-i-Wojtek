import sys
from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QApplication, QMainWindow, QFrame, QWidget, QHBoxLayout, QLabel, QPushButton, QVBoxLayout, \
    QGraphicsOpacityEffect, QLayout, QScrollArea, QComboBox, QDialog, QDesktopWidget, QSizePolicy, QSlider
from PyQt5.QtSvg import QSvgWidget
from PyQt5.QtCore import Qt, QSize
from PyQt5.QtCore import pyqtSignal, Qt
from PyQt5.QtGui import QIcon, QColor, QPixmap
import json
import time
from client import *

ca_host = 'localhost'
ca_port = 7070

sign_csr(ca_host, ca_port)
server_host = 'localhost'
server_port = 6969
server_name = "server.com"

# Utwórz kontekst SSL/TLS dla klienta
client_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
client_context.load_cert_chain(certfile="client.crt", keyfile="client.key")

# Wymaga weryfikacji certyfikatu serwera podpisanego przez zaufane CA
client_context.check_hostname = True
client_context.verify_mode = ssl.CERT_REQUIRED

# client_context.load_verify_locations(cafile="ca.crt")
client_context.load_verify_locations(cafile="client_ca.crt")
# Utwórz połączenie TCP i nawiaż połączenie SSL/TLS z serwerem
with socket.create_connection((server_host, server_port)) as client_socket:
    local_ip, local_port = client_socket.getsockname()
    with client_context.wrap_socket(client_socket, server_hostname=server_name) as ssl_socket:
        ssl.match_hostname(ssl_socket.getpeercert(), server_name)

        while True:
            class CustomToggleSwitch(QFrame):
                clicked = pyqtSignal()  # Correctly declare the signal

                def __init__(self):
                    super().__init__()
                    self.active_bg = ""
                    self.inactive_bg = ""
                    self.active_body = ""
                    self.inactive_body = ""

                    # Create the switch body frame
                    self.switch_body = QFrame(self)

                    # Set the layout
                    self.layout = QHBoxLayout(self)
                    self.layout.setContentsMargins(0, 0, 0, 0)

                    self.layout.addWidget(self.switch_body)
                    self.layout.addStretch(1)
                    # Initially place the switch body on the left
                    self.is_active = False
                    self.update_switch_position()

                    # Set the size policy
                    self.switch_body.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
                    self.update_look()

                def set_state(self, value):
                    self.is_active = value
                    self.update_switch_position()
                    self.update_look()

                def apply_style_sheets(self, active_bg, inactive_bg, active_body, inactive_body):
                    self.active_bg = active_bg
                    self.inactive_bg = inactive_bg
                    self.active_body = active_body
                    self.inactive_body = inactive_body
                    self.update_look()

                def update_look(self):
                    if self.is_active:
                        self.setStyleSheet(f'{self.active_bg}')
                        self.switch_body.setStyleSheet(f'{self.active_body}')
                    else:
                        self.setStyleSheet(f'{self.inactive_bg}')
                        self.switch_body.setStyleSheet(f'{self.inactive_body}')

                def resizeEvent(self, event):
                    # Ensure the switch body is always half the width of the parent
                    self.switch_body.setFixedWidth(self.width() // 2)
                    super().resizeEvent(event)

                def mousePressEvent(self, event):
                    # Toggle the switch position
                    self.is_active = not self.is_active
                    self.update_switch_position()
                    self.update_look()
                    self.clicked.emit()

                def update_switch_position(self):
                    self.layout.removeWidget(self.switch_body)
                    if not self.is_active:
                        self.layout.insertWidget(0, self.switch_body)
                    else:
                        self.layout.addWidget(self.switch_body)


            class CustomDialog(QDialog):
                def __init__(self, parent=None):
                    super().__init__(parent)
                    self.setWindowTitle("Logout confirmation")
                    screen = QDesktopWidget().screenGeometry()
                    width = 400
                    height = 100
                    self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)
                    # Layout
                    layout = QVBoxLayout()
                    second_layout = QHBoxLayout()

                    # Add widgets
                    self.label = QLabel("Are you sure you want to log out?")
                    layout.addWidget(self.label)

                    self.button_true = QPushButton("Yes")
                    self.button_true.clicked.connect(self.on_true_clicked)
                    second_layout.addWidget(self.button_true)

                    self.button_false = QPushButton("No")
                    self.button_false.clicked.connect(self.on_false_clicked)
                    second_layout.addWidget(self.button_false)

                    ramka = QFrame()
                    ramka.setLayout(second_layout)
                    layout.addWidget(ramka)

                    self.setLayout(layout)
                    self.setGeometry(int(screen.width() / 2) - int(width / 2), int(screen.height() / 2) - int(height / 2),
                                     width, height)

                def on_true_clicked(self):
                    self.accept()  # Return True when True button is clicked

                def on_false_clicked(self):
                    self.reject()  # Return False when False button is clicked


            class MainWindow(QMainWindow):
                def __init__(self):
                    super().__init__()
                    self.setWindowTitle("Front End")
                    self.colors = {
                        "bg-dark": "#0c0c0c",
                        "bg": "#1c1c1c",
                        "bg-light": "#363636",
                        "main-dark": "#7c0cb0",
                        "main": "#c300ff",
                        "main-light": "#d23dff",
                        "text-dark": "#c4c4c4",
                        "text": "#ffffff",
                        "red": "#e62e2e"
                    }

                    # Set the window to be maximized
                    self.setWindowState(Qt.WindowMaximized)
                    self.central_widget = QWidget()
                    self.setCentralWidget(self.central_widget)
                    layout = QHBoxLayout()
                    self.central_widget.setLayout(layout)
                    self.central_widget.layout().setContentsMargins(0, 0, 0, 0)
                    self.central_widget.setStyleSheet(f'background-color: {self.colors["bg"]};')
                    self.load_main_body()

                def closeEvent(self, event):
                    with open('program_files/settings.json') as json_file:
                        # Load JSON data from the file
                        data = json.load(json_file)
                        json_file.close()
                    if data['ask for logout']:
                        dialog = CustomDialog(self)
                        result = dialog.exec_()
                        if result == QDialog.Rejected:
                            event.ignore()

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

                def load_main_body(self):
                    side_bar = QFrame()
                    side_bar.setLayout(QVBoxLayout())
                    side_bar.setStyleSheet(
                        f'background-color: {self.colors["bg"]}; border-right:3px solid {self.colors["bg-light"]};')
                    side_bar.setFixedWidth(100)
                    self.main_body = QFrame()
                    self.main_body.setLayout(QHBoxLayout())

                    self.central_widget.layout().addWidget(side_bar)
                    self.central_widget.layout().addWidget(self.main_body, 100)

                    side_bar_buttons = []

                    user_button = QPushButton("")
                    user_button.setIcon(QIcon(QPixmap("program_files/user.png")))

                    messages_button = QPushButton("")
                    messages_button.setIcon(QIcon(QPixmap("program_files/friends.png")))

                    add_friend_button = QPushButton("")
                    add_friend_button.setIcon(QIcon(QPixmap("program_files/add_friend.png")))

                    settings_button = QPushButton("")
                    settings_button.setIcon(QIcon(QPixmap("program_files/settings.png")))

                    self.logout_button = QPushButton("")
                    self.logout_button.setIcon(QIcon(QPixmap("program_files/logoff.png")))

                    side_bar_buttons.extend([user_button, messages_button, add_friend_button, settings_button])

                    self.side_bar_functions = [self.load_user, self.load_contacts, self.load_friends_panel,
                                               self.load_settings, self.load_logout]

                    side_bar.layout().addWidget(side_bar_buttons[0])
                    side_bar_buttons[0].clicked.connect(
                        lambda checked, index=0: self.side_bar_controller(side_bar_buttons, index))
                    side_bar.layout().addWidget(side_bar_buttons[1])
                    side_bar_buttons[1].clicked.connect(
                        lambda checked, index=1: self.side_bar_controller(side_bar_buttons, index))
                    side_bar.layout().addWidget(side_bar_buttons[2])
                    side_bar_buttons[2].clicked.connect(
                        lambda checked, index=2: self.side_bar_controller(side_bar_buttons, index))
                    side_bar.layout().addStretch(1)
                    side_bar.layout().addWidget(side_bar_buttons[3])
                    side_bar_buttons[3].clicked.connect(
                        lambda checked, index=3: self.side_bar_controller(side_bar_buttons, index))
                    side_bar.layout().addWidget(self.logout_button)
                    # self.logout_button.clicked.connect(lambda checked, index=4: self.side_bar_controller(side_bar_buttons, index))
                    self.logout_button.setStyleSheet(f"QPushButton{{"
                                                     f"background:{self.colors['bg-light']};"
                                                     f"qproperty-iconSize: {55}px;"
                                                     f"border-radius:30px;"
                                                     f"border:none;"
                                                     f"}}"
                                                     f"QPushButton:hover{{"
                                                     f"background:{self.colors['red']};"
                                                     f"}}")
                    self.logout_button.setFixedSize(75, 75)
                    self.side_bar_controller(side_bar_buttons, 1)

                def side_bar_controller(self, buttons_arr, button_index):
                    for i in range(len(buttons_arr)):
                        buttons_arr[i].setStyleSheet(f"QPushButton{{"
                                                     f"background:{self.colors['bg-light']};"
                                                     f"qproperty-iconSize: {55}px;"
                                                     f"border-radius:30px;"
                                                     f"border:none;"
                                                     f"}}")
                        buttons_arr[i].setFixedSize(75, 75)

                    buttons_arr[button_index].setStyleSheet(f"QPushButton{{"
                                                            f"background:{self.colors['main-dark']};"
                                                            f"qproperty-iconSize: {55}px;"
                                                            f"border-radius:30px;"
                                                            f"border:none;"
                                                            f"}}")
                    self.side_bar_functions[button_index]()
                    # if button_index == 4:
                    #     self.side_bar_functions[button_index]()
                    # else:
                    #     self.side_bar_functions[button_index]()

                def load_user(self):
                    self.reset_widget(self.main_body)

                def load_contacts(self):
                    self.reset_widget(self.main_body)

                def load_friends_panel(self):
                    self.reset_widget(self.main_body)

                def load_settings(self):
                    with open('program_files/settings.json') as json_file:
                        data = json.load(json_file)

                    scroll = QScrollArea()
                    elements_wrapper = QWidget()
                    elements_layout = QVBoxLayout(elements_wrapper)

                    for key in data:
                        name = QLabel(key)
                        name.setStyleSheet(
                            f"QLabel {{ color: {self.colors['text']}; font-size:20px;}}")  # Example label styling
                        element = QFrame()
                        element_layout = QHBoxLayout(element)
                        element_layout.addWidget(name)
                        element.setStyleSheet(
                            f"QFrame {{ background-color: {self.colors['bg-light']}; border: none; }}")
                        element.setFixedHeight(50)

                        elements_layout.addWidget(element)
                        element.setFixedWidth(600)
                        if type(data[key]) == type(False):
                            print("generate_bool")
                            print(data[key])
                            element.layout().addWidget(CustomToggleSwitch())
                            switch = element.children()[-1]

                            switch.apply_style_sheets(
                                active_bg=f'background-color: {self.colors["main"]}; border-radius:14px;',
                                active_body=f'background-color: {self.colors["text"]}; border-radius:14px;',
                                inactive_bg=f'background-color: {self.colors["bg-dark"]}; border-radius:14px;',
                                inactive_body=f'background-color: {self.colors["text"]}; border-radius:14px;')
                            switch.setFixedWidth(100)
                            switch.set_state(data["ask for logout"])

                        if type(data[key]) == type(0.0):
                            print("generate_float")
                            print(int(data[key] * 100))
                            element.layout().addWidget(QSlider(Qt.Horizontal, self))
                            switch = element.children()[-1]
                            switch.setMinimum(1)
                            switch.setMaximum(100)
                            switch.setValue(int(data[key] * 100))
                            switch.setFixedWidth(290)
                            switch.setStyleSheet(f"QSlider::handle:horizontal {{background: {self.colors['main']};}}")

                        if type(data[key]) == type({}):
                            print("generate_options")
                            print(data[key]['list'][data[key]['value']])
                            element.layout().addWidget(QComboBox())
                            switch = element.children()[-1]
                            switch.setStyleSheet(f"color: {self.colors['text']}; font-size:20px;")
                            for element in data[key]['list']:
                                switch.addItem(f'{element}')
                            switch.setCurrentIndex(data[key]['value'])

                    def get_settings():
                        temp = []
                        for element in elements_wrapper.children()[1:-1]:
                            if type(element.children()[-1]) == type(CustomToggleSwitch()):
                                temp.append(element.children()[-1].is_active)

                            if type(element.children()[-1]) == type(QSlider()):
                                temp.append(element.children()[-1].value() / 100)

                            if type(element.children()[-1]) == type(QComboBox()):
                                temp.append(element.children()[-1].currentIndex())

                        for i in range(len(list(data.keys()))):
                            if type(data[list(data.keys())[i]]) == type({}):
                                data[list(data.keys())[i]]['value'] = temp[i]
                            else:
                                data[list(data.keys())[i]] = temp[i]

                        with open('program_files/settings.json', 'w') as json_file:
                            json.dump(data, json_file, indent=4)

                    apply_button = QPushButton("Apply")
                    apply_button.clicked.connect(get_settings)
                    elements_wrapper.layout().addWidget(apply_button)
                    apply_button.setFixedWidth(600)
                    apply_button.setStyleSheet(
                        f'background: {self.colors["main"]}; color:{self.colors["text"]}; font-size:20px;')
                    elements_wrapper.layout().addStretch(1)

                    scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOn)
                    scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
                    scroll.setWidgetResizable(True)
                    scroll.setWidget(elements_wrapper)
                    scroll.setStyleSheet(f'QScrollBar:vertical{{'
                                         f'border: none;'
                                         f'background-color: {self.colors["bg-dark"]};'
                                         f'width: 15px;'
                                         f'margin:0;'
                                         f'}}'
                                         f'QScrollBar::handle:vertical{{'
                                         f'background-color: {self.colors["main"]};'
                                         f'min-height: 30px;'
                                         f'}}'
                                         f'QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical{{'
                                         f'border: none;'
                                         f'background: none;'
                                         f'width: 0;'
                                         f'height: 0;'
                                         f'}}')

                    self.reset_widget(self.main_body)

                    self.main_body.layout().addWidget(scroll)

                def load_logout(self):
                    pass
                    # self.side_bar_controller(self.central_widget.children()[1].children()[:][1:], self.last_page_index)

                def premision_to_leave(self):
                    app = QApplication(sys.argv)
                    dialog = CustomDialog()
                    result = dialog.exec_()
                    return result == QDialog.Accepted


            import sys
            from PyQt5.QtWidgets import QApplication, QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout, QMessageBox


            class LoginWindow(QMainWindow):
                def __init__(self):
                    super().__init__()
                    self.setWindowTitle('Login')
                    self.colors = {
                        "bg-dark": "#0c0c0c",
                        "bg": "#1c1c1c",
                        "bg-light": "#363636",
                        "main-dark": "#7c0cb0",
                        "main": "#c300ff",
                        "main-light": "#d23dff",
                        "text-dark": "#c4c4c4",
                        "text": "#ffffff",
                        "red": "#e62e2e"
                    }
                    self.width = 500
                    self.height = 600
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
                    self.central_widget.setStyleSheet(f'background-color: {self.colors["bg"]};')
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
                    self.reset_widget(self.central_widget)
                    login_input = QLineEdit()
                    login_input.setPlaceholderText("Login")
                    login_input.setStyleSheet(
                        f'background: {self.colors["bg-light"]}; color: {self.colors["text"]}; font-size:20px;')
                    login_input.setFixedWidth(400)
                    pass_input = QLineEdit()
                    pass_input.setPlaceholderText("Password")
                    pass_input.setStyleSheet(
                        f'background: {self.colors["bg-light"]}; color: {self.colors["text"]}; font-size:20px;')
                    pass_input.setFixedWidth(400)
                    self.login_inputs = [login_input, pass_input]

                    login_button = QPushButton("Login")
                    login_button.clicked.connect(self.login)
                    login_button.setStyleSheet(
                        f'background: {self.colors["main"]}; color: {self.colors["text"]}; font-size:20px;')
                    login_button.setFixedWidth(200)
                    register_button = QPushButton("Register")
                    register_button.clicked.connect(self.load_register)
                    register_button.setStyleSheet(
                        f'background: {self.colors["bg-light"]}; color: {self.colors["text"]}; font-size:20px;')
                    register_button.setFixedWidth(200)

                    layout = self.central_widget.layout()
                    layout.setSpacing(20)
                    layout.addWidget(login_input, alignment=Qt.AlignCenter)
                    layout.addWidget(pass_input, alignment=Qt.AlignCenter)
                    layout.addWidget(login_button, alignment=Qt.AlignCenter)
                    layout.addWidget(register_button, alignment=Qt.AlignCenter)
                    layout.setAlignment(Qt.AlignCenter)

                def load_register(self):
                    self.reset_widget(self.central_widget)
                    login_input = QLineEdit()
                    login_input.setPlaceholderText("Login")
                    login_input.setStyleSheet(
                        f'background: {self.colors["bg-light"]}; color: {self.colors["text"]}; font-size:20px;')
                    login_input.setFixedWidth(400)
                    pass_input = QLineEdit()
                    pass_input.setPlaceholderText("Password")
                    pass_input.setStyleSheet(
                        f'background: {self.colors["bg-light"]}; color: {self.colors["text"]}; font-size:20px;')
                    pass_input.setFixedWidth(400)

                    second_pass_input = QLineEdit()
                    second_pass_input.setPlaceholderText("Password again")
                    second_pass_input.setStyleSheet(
                        f'background: {self.colors["bg-light"]}; color: {self.colors["text"]}; font-size:20px;')
                    second_pass_input.setFixedWidth(400)

                    login_button = QPushButton("Login")
                    login_button.clicked.connect(self.load_login)
                    login_button.setStyleSheet(
                        f'background: {self.colors["bg-light"]}; color: {self.colors["text"]}; font-size:20px;')
                    login_button.setFixedWidth(200)
                    register_button = QPushButton("Register")
                    register_button.clicked.connect(lambda: print("registerer attempt"))
                    register_button.setStyleSheet(
                        f'background: {self.colors["main"]}; color: {self.colors["text"]}; font-size:20px;')
                    register_button.setFixedWidth(200)

                    layout = self.central_widget.layout()
                    layout.setSpacing(20)
                    layout.addWidget(login_input, alignment=Qt.AlignCenter)
                    layout.addWidget(pass_input, alignment=Qt.AlignCenter)
                    layout.addWidget(second_pass_input, alignment=Qt.AlignCenter)
                    layout.addWidget(register_button, alignment=Qt.AlignCenter)
                    layout.addWidget(login_button, alignment=Qt.AlignCenter)
                    layout.setAlignment(Qt.AlignCenter)

                def login(self):
                    print(self.login_inputs[0].text())
                    # ph = PasswordHasher()
                    # data = {"header": "login", 'username': username, 'password': password}
                    # # hashed_password = ph.hash(password)
                    # data = json.dumps(data, indent=4)
                    # return data

            if __name__ == '__main__':
                app = QApplication(sys.argv)
                login_window = LoginWindow()
                login_window.show()
                sys.exit(app.exec_())
