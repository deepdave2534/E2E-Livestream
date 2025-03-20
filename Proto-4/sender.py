import socket
import cv2
import numpy as np
import threading
import pickle
import tkinter as tk
import hashlib
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

server_socket = None
clients = []
streaming = False
aes_keys = {}

def handle_client(conn, addr, private_key):
    global aes_keys
    print(f"[*] New receiver connected from {addr}")
    try:
        public_key = private_key.publickey().export_key()
        conn.send(public_key)
        encrypted_aes_key = conn.recv(256)
        cipher_rsa = PKCS1_OAEP.new(private_key)
        aes_key = cipher_rsa.decrypt(encrypted_aes_key)
        aes_keys[conn] = aes_key
        print(f"[*] AES key exchanged successfully with {addr}")
        clients.append(conn)
    except Exception as e:
        print(f"[!] Error handling client {addr}: {e}")
        conn.close()

def start_stream():
    global server_socket, streaming
    SERVER_IP = "0.0.0.0"
    PORT = 5000

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((SERVER_IP, PORT))
    server_socket.listen(5)
    print("[*] Waiting for connections...")

    rsa_key = RSA.generate(2048)

    def accept_clients():
        while streaming:
            try:
                conn, addr = server_socket.accept()
                threading.Thread(target=handle_client, args=(conn, addr, rsa_key)).start()
            except:
                break

    threading.Thread(target=accept_clients, daemon=True).start()
    cap = cv2.VideoCapture(0)
    streaming = True

    try:
        while streaming and cap.isOpened():
            ret, frame = cap.read()
            if not ret:
                break

            _, buffer = cv2.imencode('.jpg', frame)
            frame_bytes = buffer.tobytes()
            frame_hash = hashlib.sha256(frame_bytes).digest()

            for conn in list(clients):
                try:
                    aes_key = aes_keys[conn]
                    cipher_aes = AES.new(aes_key, AES.MODE_EAX)
                    nonce = cipher_aes.nonce
                    encrypted_frame, tag = cipher_aes.encrypt_and_digest(frame_bytes)

                    # Send (nonce, tag, encrypted_frame, hash) together
                    data_packet = pickle.dumps((nonce, tag, encrypted_frame, frame_hash))
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

def start_stream_thread():
    global streaming
    if not streaming:
        streaming = True
        threading.Thread(target=start_stream, daemon=True).start()

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

# UI
root = tk.Tk()
root.title("Encrypted Livestream - Sender")

tk.Button(root, text="Start Call", command=start_stream_thread, bg="green", fg="white", font=("Arial", 14)).pack(pady=10)
tk.Button(root, text="End Call", command=stop_stream, bg="red", fg="white", font=("Arial", 14)).pack(pady=10)

root.mainloop()
