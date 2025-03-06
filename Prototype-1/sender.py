import socket
import cv2
import numpy as np
import threading
import pickle
import tkinter as tk
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

# Global variables
server_socket = None
clients = []  # List to store connected clients
streaming = False
aes_keys = {}  # Store AES keys for each client

# Function to handle a new client
def handle_client(conn, addr, private_key):
    global aes_keys

    print(f"[*] New receiver connected from {addr}")

    try:
        # Send public key
        public_key = private_key.publickey().export_key()
        conn.send(public_key)

        # Receive encrypted AES key from receiver
        encrypted_aes_key = conn.recv(256)
        
        # Decrypt AES Key
        cipher_rsa = PKCS1_OAEP.new(private_key)
        aes_key = cipher_rsa.decrypt(encrypted_aes_key)
        aes_keys[conn] = aes_key  # Store AES key for this client

        print(f"[*] AES key exchanged successfully with {addr}")

        # Add client to list
        clients.append(conn)

    except Exception as e:
        print(f"[!] Error handling client {addr}: {e}")
        conn.close()

# Function to start the livestream
def start_stream():
    global server_socket, streaming

    SERVER_IP = "0.0.0.0"  # Listen on all available interfaces
    PORT = 5000

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((SERVER_IP, PORT))
    server_socket.listen(5)  # Allow multiple connections
    print("[*] Waiting for connections...")

    # Generate RSA key pair
    rsa_key = RSA.generate(2048)

    # Accept multiple clients in a separate thread
    def accept_clients():
        while streaming:
            try:
                conn, addr = server_socket.accept()
                threading.Thread(target=handle_client, args=(conn, addr, rsa_key)).start()
            except:
                break

    # Start accepting clients in background
    threading.Thread(target=accept_clients, daemon=True).start()

    # Start video capture
    cap = cv2.VideoCapture(0)
    streaming = True

    try:
        while streaming and cap.isOpened():
            ret, frame = cap.read()
            if not ret:
                break

            _, buffer = cv2.imencode('.jpg', frame)
            frame_bytes = buffer.tobytes()

            # Encrypt and send to all clients
            for conn in list(clients):
                try:
                    aes_key = aes_keys[conn]
                    cipher_aes = AES.new(aes_key, AES.MODE_EAX)
                    nonce = cipher_aes.nonce
                    encrypted_frame, tag = cipher_aes.encrypt_and_digest(frame_bytes)

                    # Create packet
                    data_packet = pickle.dumps((nonce, tag, encrypted_frame))
                    conn.send(len(data_packet).to_bytes(4, 'big'))
                    conn.sendall(data_packet)
                except Exception:
                    print(f"[!] Removing client {conn.getpeername()}")
                    clients.remove(conn)
                    conn.close()

            cv2.imshow("Sending Video", frame)
            if cv2.waitKey(1) & 0xFF == ord('q'):
                break

    finally:
        cap.release()
        server_socket.close()
        cv2.destroyAllWindows()
        print("[*] Stream stopped.")

# Function to start stream in a separate thread
def start_stream_thread():
    global streaming
    if not streaming:
        streaming = True
        threading.Thread(target=start_stream, daemon=True).start()

# Function to stop the stream
def stop_stream():
    global streaming
    streaming = False
    for conn in clients:
        conn.close()
    clients.clear()
    print("[*] Stopping stream...")
    if server_socket:
        server_socket.close()
    root.quit()

# UI Setup
root = tk.Tk()
root.title("Encrypted Livestream - Sender")

tk.Button(root, text="Start Call", command=start_stream_thread, bg="green", fg="white", font=("Arial", 14)).pack(pady=10)
tk.Button(root, text="End Call", command=stop_stream, bg="red", fg="white", font=("Arial", 14)).pack(pady=10)

root.mainloop()
