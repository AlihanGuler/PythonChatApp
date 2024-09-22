import socket
import threading
import json
import time
import datetime
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_parameters, Encoding, PublicFormat

UDP_SERVER_ADDRESS = "localhost"
UDP_SERVER_PORT = ""
TCP_SERVER_PORT = ""
LOG_FILE = "chat_log.txt"

def log_message(username, message, direction):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as log_file:
        log_file.write(f"{timestamp} - {username} - {direction} - {message}\n")

def get_name():
    name = input("Please enter a username: ")
    return name.strip()

def list_users(name):
    try:
        udp_client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        payload = f"ONLINE:{name}"
        udp_client.sendto(payload.encode(), (UDP_SERVER_ADDRESS, UDP_SERVER_PORT))
        response, _ = udp_client.recvfrom(1024)
        users = json.loads(response.decode())
        if users:
            print("Online Users:")
            for user in users:
                print(f"- {user}")
        else:
            print("No users are currently online.")
        udp_client.close()
    except Exception as e:
        print(f"An error occurred: {e}")

def start_tcp_server():
    tcp_client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tcp_client.sendto(b'START_TCP_SERVER', (UDP_SERVER_ADDRESS, UDP_SERVER_PORT))
    tcp_client.close()

def secure_chat(name):
    start_tcp_server()
    print("TCP connection started.")
    time.sleep(1)  # Wait for the TCP server to start

    conn = socket.create_connection((UDP_SERVER_ADDRESS, TCP_SERVER_PORT))

    # Get parameters and public key from the server
    data = conn.recv(1024)
    if data:
        message = data.decode()
        params_pem = json.loads(message)["params"]
        peer_public_key_pem = json.loads(message)["key"]

        parameters = load_pem_parameters(params_pem.encode())
        private_key = parameters.generate_private_key()
        public_key = private_key.public_key()

        # Send public key in JSON format
        public_key_bytes = public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
        conn.send(json.dumps({"key": public_key_bytes}).encode())

        peer_public_key = load_pem_public_key(peer_public_key_pem.encode())
        print(f"Received peer public key: {peer_public_key}")
        shared_key = private_key.exchange(peer_public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data'
        ).derive(shared_key)
        print(f"Key exchange completed: {derived_key}")

        while True:
            text = input("Enter your message (type 'exit' to quit): ")
            if text == "exit":
                break
            cipher = Cipher(algorithms.AES(derived_key), modes.CFB8(derived_key[:16]))
            encryptor = cipher.encryptor()
            encrypted_message = encryptor.update(text.encode()) + encryptor.finalize()
            conn.send(json.dumps({"encryptedmessage": encrypted_message.hex()}).encode())
            log_message(name, text, "SENT")
    
    conn.close()

def unsecure_chat(name):
    start_tcp_server()
    print("TCP connection started.")
    time.sleep(1)  # Wait for the TCP server to start

    conn = socket.create_connection((UDP_SERVER_ADDRESS, TCP_SERVER_PORT))

    def receive_messages():
        while True:
            try:
                data = conn.recv(1024)
                if data:
                    response = json.loads(data.decode())
                    print(f"{response['sender']}: {response['unencryptedmessage']}")
                    log_message(response['sender'], response['unencryptedmessage'], "RECEIVED")
            except Exception as e:
                print(f"Error receiving message: {e}")
                break

    threading.Thread(target=receive_messages, daemon=True).start()

    while True:
        text = input("Enter your message (type 'exit' to quit): ")
        if text == "exit":
            break
        message = json.dumps({"sender": name, "unencryptedmessage": text})
        print(f"Sent message: {message}")
        conn.send(message.encode())
        log_message(name, text, "SENT")

    conn.close()

def display_chat_history():
    try:
        with open(LOG_FILE, "r") as log_file:
            print("\nChat History:")
            for line in log_file:
                print(line.strip())
    except FileNotFoundError:
        print("No chat history found.")

def main():
    name = get_name()
    print(f"Welcome, {name}!")

    while True:
        print("\nMenu:")
        print("1. List Users")
        print("2. Chat")
        print("3. Chat History")
        print("4. Exit")
        choice = input("Please make a selection: ")

        if choice == "1":
            list_users(name)
        elif choice == "2":
            chat_choice = input("Enter 'unsecure' for unsecure chat: ")
            if chat_choice == "unsecure":
                unsecure_chat(name)
            else:
                print("Invalid selection.")
        elif choice == "3":
            display_chat_history()
        elif choice == "4":
            print("Exiting...")
            break
        else:
            print("Invalid selection. Please try again.")

if __name__ == "__main__":
    main()
