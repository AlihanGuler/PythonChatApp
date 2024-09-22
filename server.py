import socket
import threading
import queue
import json
import time
import datetime
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_pem_public_key, Encoding, PublicFormat, ParameterFormat

LOG_FILE = "chat_log.txt"
with open(LOG_FILE, "w") as log_file:
    log_file.write("")
messages = queue.Queue()
clients = {}
offline_users = []
server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.bind(("localhost", ""))

last_seen = {}
tcp_server_started = threading.Event()  # Event to signal the TCP server has started

def log_message(username, message, direction):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as log_file:
        log_file.write(f"{timestamp} - {username} - {direction} - {message}\n")

def receive():
    while True:
        try:
            message, addr = server.recvfrom(1024)
            if message == b'START_TCP_SERVER':
                start_tcp_server_thread()
            else:
                messages.put((message, addr))
        except Exception as e:
            print(f"Error received: {e}")

def broadcast():
    while True:
        while not messages.empty():
            message, addr = messages.get()
            payload = message.decode()
            print(payload)

            if addr not in clients:
                if payload.startswith("ONLINE:"):
                    name = payload.split(":")[1]
                    clients[addr] = name
                    print(f"{name} joined the server.")
                    for client in clients:
                        if client != addr:
                            server.sendto(json.dumps({"action": "join", "name": name}).encode(), client)
                    last_seen[addr] = time.time()
                    online_users = list(clients.values())
                    server.sendto(json.dumps(online_users).encode(), addr)
                else:
                    print("Invalid message: ONLINE expected.")
                continue

            if payload.startswith("OFFLINE:"):
                name = payload.split(":")[1]
                if addr in clients:
                    del clients[addr]
                    del last_seen[addr]
                    offline_users.append(name)
                    print(f"{name} left the server.")
                    for client in clients:
                        server.sendto(json.dumps({"action": "leave", "name": name}).encode(), client)

            last_seen[addr] = time.time()

            for client_addr, name in clients.items():
                try:
                    if not payload.startswith("ONLINE:") and not payload.startswith("OFFLINE:"):
                        server.sendto(message, client_addr)
                except Exception as e:
                    print(f"Error received: {e}")
                    del clients[client_addr]
                    del last_seen[client_addr]

        current_time = time.time()
        for client_addr, last_time in list(last_seen.items()):
            if current_time - last_time > 10:
                if client_addr in clients:
                    name = clients[client_addr]
                    del clients[client_addr]
                    del last_seen[client_addr]
                    offline_users.append(name)
                    print(f"{name} away.")
                    for client in clients:
                        server.sendto(json.dumps({"action": "leave", "name": name}).encode(), client)

def print_online_offline_users():
    while True:
        time.sleep(10)  # List users every 30 seconds
        if clients or offline_users:
            print("\nOnline Users:")
            for addr, name in clients.items():
                print(f"- {name} (IP: {addr[0]}, Port: {addr[1]})")
            print("\nOffline Users:")
            for user in offline_users:
                print(f"- {user}")

def start_tcp_server():
    tcp_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_server.bind(("localhost", 9998))
    tcp_server.listen(5)
    print("TCP server started, waiting for connections...")
    tcp_server_started.set()  # Signal that the TCP server has started
    while True:
        conn, addr = tcp_server.accept()
        print(f"Connection received: {addr}")
        clients[addr] = conn
        threading.Thread(target=handle_client, args=(conn, addr)).start()

def handle_client(conn, addr):
    try:
        while True:
            data = conn.recv(1024)
            if not data:
                break
            message = json.loads(data.decode())
            if "unencryptedmessage" in message:
                handle_unsecure_chat(conn, addr, message)
            elif "key" in message:
                handle_secure_chat(conn, addr, message)
            else:
                print(f"Unknown message type: {message}")
    except Exception as e:
        print(f"Connection error: {e}")
    finally:
        del clients[addr]
        conn.close()
        print(f"Connection closed: {addr}")

def handle_secure_chat(conn, addr, message):
    parameters = dh.generate_parameters(generator=2, key_size=512)
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()

    params_pem = parameters.parameter_bytes(Encoding.PEM, ParameterFormat.PKCS3).decode()
    public_key_bytes = public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
    conn.send(json.dumps({"params": params_pem, "key": public_key_bytes}).encode())

    peer_key_bytes = message["key"]
    peer_public_key = load_pem_public_key(peer_key_bytes.encode())
    shared_key = private_key.exchange(peer_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data'
    ).derive(shared_key)
    print(f"Key exchange completed: {derived_key}")

    while True:
        data = conn.recv(1024)
        if not data:
            break
        message = json.loads(data.decode())
        if "encryptedmessage" in message:
            encrypted_message = message["encryptedmessage"]
            cipher = Cipher(algorithms.AES(derived_key), modes.CFB8(derived_key[:16]))
            decryptor = cipher.decryptor()
            decrypted_message = decryptor.update(bytes.fromhex(encrypted_message)) + decryptor.finalize()
            decrypted_text = decrypted_message.decode()
            print(f"Encrypted message received: {decrypted_text}")
            log_message("Peer", decrypted_text, "RECEIVED")
        else:
            print(f"Unknown message type: {message}")

def handle_unsecure_chat(conn, addr, message):
    try:
        sender = message['sender']
        msg = message['unencryptedmessage']
        print(f"{sender}: {msg}")
        response = json.dumps({"sender": sender, "unencryptedmessage": msg})
        print(f"Sent message: {response}")
        log_message(sender, msg, "RECEIVED")
        for client_addr, client_conn in clients.items():
            if client_addr != addr:
                client_conn.send(response.encode())
    except Exception as e:
        print(f"Message handling error: {e}")

def start_tcp_server_thread():
    global tcp_server_started
    if not tcp_server_started.is_set():
        threading.Thread(target=start_tcp_server).start()

# Start threads
t1 = threading.Thread(target=receive)
t2 = threading.Thread(target=broadcast)
t3 = threading.Thread(target=print_online_offline_users)

t1.start()
t2.start()
t3.start()