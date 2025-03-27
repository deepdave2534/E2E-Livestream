import socket
import cv2
import numpy as np
import tkinter as tk
import hashlib
import hmac
from threading import Thread
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
import pickle
import struct

client_socket = None
streaming = False
HMAC_SECRET_KEY = b'super_secure_key'  # Must match sender's HMAC key

def verify_hmac(tag, encrypted_frame, received_hmac):
    """ Verify HMAC integrity """
    expected_hmac = hmac.new(HMAC_SECRET_KEY, tag + encrypted_frame, hashlib.sha256).digest()
    return hmac.compare_digest(expected_hmac, received_hmac)

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
            packet_size_bytes = client_socket.recv(4)
            if not packet_size_bytes:
                print("[!] Disconnected from sender.")
                break

            packet_size = struct.unpack(">I", packet_size_bytes)[0]
            data_packet = client_socket.recv(packet_size)

            try:
                nonce, tag, encrypted_frame, frame_hash, received_hmac = pickle.loads(data_packet)

                if not verify_hmac(tag, encrypted_frame, received_hmac):
                    print("[❌] HMAC verification failed! Possible tampering detected.")
                    continue

                cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
                decrypted_frame = cipher_aes.decrypt_and_verify(encrypted_frame, tag)

                computed_hash = hashlib.sha256(decrypted_frame).digest()
                if computed_hash != frame_hash:
                    print("[❌] Frame hash mismatch! Possible tampering detected.")
                    continue

                frame = np.frombuffer(decrypted_frame, dtype=np.uint8)
                frame = cv2.imdecode(frame, cv2.IMREAD_COLOR)
                if frame is None:
                    continue

                cv2.imshow("Encrypted Stream", frame)
                if cv2.waitKey(1) & 0xFF == ord('q'):
                    break

            except Exception:
                print("[❌] Frame decoding error. Skipping frame.")
                continue

    finally:
        client_socket.close()
        cv2.destroyAllWindows()
        print("[*] Stream stopped.")

root = tk.Tk()
root.title("Encrypted Livestream - Receiver")

tk.Button(root, text="Receive Call", command=start_receive, bg="blue", fg="white", font=("Arial", 14)).pack(pady=10)
tk.Button(root, text="End Call", command=root.quit, bg="red", fg="white", font=("Arial", 14)).pack(pady=10)

root.mainloop()
