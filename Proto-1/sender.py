import socket
import cv2
import numpy as np
import pickle
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Global Variables
SERVER_IP = "0.0.0.0"
PORT = 5000

# Start server
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((SERVER_IP, PORT))
server_socket.listen(1)
print("[*] Waiting for connection...")

conn, addr = server_socket.accept()
print(f"[*] Connected to {addr}")

# Generate RSA Keys
rsa_key = RSA.generate(2048)
private_key = rsa_key.export_key()
public_key = rsa_key.publickey().export_key()

# Send Public Key to Receiver/Spoofer
conn.send(public_key)

# Receive Encrypted AES Key
encrypted_aes_key = conn.recv(256)

# Decrypt AES Key
cipher_rsa = PKCS1_OAEP.new(RSA.import_key(private_key))
aes_key = cipher_rsa.decrypt(encrypted_aes_key)
print("[*] AES Key successfully exchanged!")

# Start capturing video
cap = cv2.VideoCapture(0)
if not cap.isOpened():
    print("[!] Failed to access camera.")
    exit()

while True:
    ret, frame = cap.read()
    if not ret:
        break

    # Convert frame to bytes
    _, buffer = cv2.imencode('.jpg', frame)
    frame_bytes = buffer.tobytes()

    # Print original frame hash (debugging)
    print(f"[SENDER] Captured Frame Hash: {hash(frame_bytes)}")

    # Encrypt frame
    cipher_aes = AES.new(aes_key, AES.MODE_EAX)
    nonce = cipher_aes.nonce
    encrypted_frame, tag = cipher_aes.encrypt_and_digest(frame_bytes)

    # Print partial encrypted frame data
    print(f"[SENDER] Encrypted Frame (first 20 bytes): {encrypted_frame[:20]}")
    print(f"[SENDER] Nonce: {nonce.hex()} | Tag: {tag.hex()}")

    # Send encrypted data
    packet = pickle.dumps((nonce, tag, encrypted_frame))
    conn.send(len(packet).to_bytes(4, 'big'))  # Send length first
    conn.sendall(packet)

    # Show original video on sender side
    cv2.imshow("Sending Video", frame)
    if cv2.waitKey(1) & 0xFF == ord('q'):
        break

# Cleanup
cap.release()
conn.close()
server_socket.close()
cv2.destroyAllWindows()
print("[*] Stream stopped.")
