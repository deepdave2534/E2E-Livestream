import socket
import cv2
import numpy as np
import pickle
import struct
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

# Global variables
SERVER_IP = "0.0.0.0"
PORT = 5000

# Generate RSA key pair (sender's private & public key)
rsa_key = RSA.generate(2048)
private_key = rsa_key.export_key()
public_key = rsa_key.publickey().export_key()

# Start server
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((SERVER_IP, PORT))
server_socket.listen(5)
print("[*] Waiting for connection...")

conn, addr = server_socket.accept()
print(f"[*] Connected to {addr}")

# Send public key to the receiver
conn.send(public_key)

# Generate authentication challenge
challenge = get_random_bytes(16)
challenge_hash = SHA256.new(challenge)

# Sign challenge with sender's private key
signature = pkcs1_15.new(RSA.import_key(private_key)).sign(challenge_hash)

# Send challenge and signature
conn.send(pickle.dumps((challenge, signature)))

# Receive verification result
auth_result = conn.recv(1)
if auth_result != b'1':
    print("[❌] Authentication failed! Disconnecting...")
    conn.close()
    server_socket.close()
    exit()

print("[✅] Authentication successful! Starting video stream...")

# Generate AES Key and send to receiver
aes_key = get_random_bytes(16)
cipher_rsa = PKCS1_OAEP.new(RSA.import_key(public_key))
encrypted_aes_key = cipher_rsa.encrypt(aes_key)
conn.send(encrypted_aes_key)

# Start video capture
cap = cv2.VideoCapture(0)

while cap.isOpened():
    ret, frame = cap.read()
    if not ret:
        break

    _, buffer = cv2.imencode('.jpg', frame)
    frame_bytes = buffer.tobytes()

    # Encrypt frame
    cipher_aes = AES.new(aes_key, AES.MODE_EAX)
    nonce = cipher_aes.nonce
    encrypted_frame, tag = cipher_aes.encrypt_and_digest(frame_bytes)

    # Send encrypted frame
    data_packet = pickle.dumps((nonce, tag, encrypted_frame))
    conn.send(struct.pack(">I", len(data_packet)))  # Send size
    conn.sendall(data_packet)

    cv2.imshow("Sending Video", frame)
    if cv2.waitKey(1) & 0xFF == ord('q'):
        break

cap.release()
conn.close()
server_socket.close()
cv2.destroyAllWindows()
print("[*] Stream stopped.")
