import json
import secrets
import socket
import ssl
import threading
import time
from hashlib import sha256
from Crypto.Cipher import AES
from sympy import randprime, primitive_root
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