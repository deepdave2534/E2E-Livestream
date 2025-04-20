import socket
import cv2
import numpy as np
import tkinter as tk
import hashlib
from threading import Thread
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
import pickle
import struct

client_socket = None
streaming = False

def recv_exact(sock, size):
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            return None
        data += chunk
    return data

def start_receive():
    global client_socket, streaming
    SERVER_IP = "127.0.0.1"
    PORT = 5000

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((SERVER_IP, PORT))

    public_key = client_socket.recv(2048)
    aes_key = get_random_bytes(16)
    cipher_rsa = PKCS1_OAEP.new(RSA.import_key(public_key))
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    client_socket.send(encrypted_aes_key)

    print("[*] AES Key successfully exchanged!")
    streaming = True

    try:
        while streaming:
            packet_size_bytes = recv_exact(client_socket, 4)
            if not packet_size_bytes:
                print("[!] Disconnected from sender.")
                break

            packet_size = struct.unpack(">I", packet_size_bytes)[0]
            data_packet = recv_exact(client_socket, packet_size)
            if not data_packet:
                print("[!] Lost connection or incomplete frame.")
                break

            try:
                nonce, tag, encrypted_frame, frame_hash = pickle.loads(data_packet)
                cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
                decrypted_frame = cipher_aes.decrypt_and_verify(encrypted_frame, tag)

                # Hash verification
                computed_hash = hashlib.sha256(decrypted_frame).digest()
                if computed_hash != frame_hash:
                    print("[] Frame hash mismatch! Possible tampering detected. Skipping frame.")
                    continue

                frame = np.frombuffer(decrypted_frame, dtype=np.uint8)
                frame = cv2.imdecode(frame, cv2.IMREAD_COLOR)
                if frame is None:
                    print("[] Decoding failed. Skipping frame.")
                    continue

                cv2.imshow("Encrypted Stream", frame)
                if cv2.waitKey(1) & 0xFF == ord('q'):
                    break

            except (ValueError, pickle.UnpicklingError) as e:
                print(f"[] Frame decoding error: {e}. Skipping frame.")
                continue

    except Exception as e:
        print(f"[!] Error: {e}")

    finally:
        client_socket.close()
        cv2.destroyAllWindows()
        print("[*] Stream stopped.")

def stop_receive():
    global streaming
    streaming = False
    print("[*] Stopping stream...")
    if client_socket:
        client_socket.close()
    root.quit()

def start_receive_thread():
    thread = Thread(target=start_receive)
    thread.start()

root = tk.Tk()
root.title("Encrypted Livestream - Receiver")

tk.Button(root, text="Receive Call", command=start_receive_thread, bg="blue", fg="white", font=("Arial", 14)).pack(pady=10)
tk.Button(root, text="End Call", command=stop_receive, bg="red", fg="white", font=("Arial", 14)).pack(pady=10)

root.mainloop()
