import socket
import cv2
import numpy as np
import pickle
import struct
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Global Variables
SERVER_IP = "127.0.0.1"  # Tries spoofing
PORT = 5000

# Connect to sender
receiver_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
receiver_socket.connect((SERVER_IP, PORT))
print("[*] Receiver connected to sender.")

# Receive Sender's Public Key
public_key = receiver_socket.recv(2048)

# Generate AES Key
aes_key = AES.get_random_bytes(16)  # Correct AES Key

# Encrypt AES Key with Sender's Public Key
cipher_rsa = PKCS1_OAEP.new(RSA.import_key(public_key))
encrypted_aes_key = cipher_rsa.encrypt(aes_key)

# Send Encrypted AES Key
receiver_socket.send(encrypted_aes_key)
print("[*] Receiver successfully exchanged AES key.")

while True:
    # Receive packet size (4 bytes)
    packet_size_bytes = receiver_socket.recv(4)
    if not packet_size_bytes:
        print("[!] Sender disconnected.")
        break

    packet_size = struct.unpack(">I", packet_size_bytes)[0]
    print(f"[RECEIVER] Received Packet Size: {packet_size} bytes")

    # Receive encrypted data
    data_packet = receiver_socket.recv(packet_size)

    # Deserialize received packet
    nonce, tag, encrypted_frame = pickle.loads(data_packet)

    # Print partial received encrypted frame data
    print(f"[RECEIVER] Received Encrypted Frame (first 20 bytes): {encrypted_frame[:20]}")
    print(f"[RECEIVER] Nonce: {nonce.hex()} | Tag: {tag.hex()}")

    try:
        # Decrypt frame
        cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
        decrypted_frame = cipher_aes.decrypt_and_verify(encrypted_frame, tag)

        # Print decrypted frame hash (to verify integrity)
        print(f"[RECEIVER] Decrypted Frame Hash: {hash(decrypted_frame)}")

        # Convert bytes to image
        frame = np.frombuffer(decrypted_frame, dtype=np.uint8)
        frame = cv2.imdecode(frame, cv2.IMREAD_COLOR)

        # Show the actual video stream
        cv2.imshow("Decrypted Stream", frame)

    except ValueError:
        print("[❌] Decryption failed! Possible data corruption.")

    if cv2.waitKey(1) & 0xFF == ord('q'):
        break

# Cleanup
receiver_socket.close()
cv2.destroyAllWindows()
print("[*] Receiver disconnected.")
