import socket
import cv2
import numpy as np
import pickle
import struct
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

# Global Variables
SERVER_IP = "127.0.0.1"  # Spoofer connects as a client
PORT = 5000

# Connect to sender
spoofer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
spoofer_socket.connect((SERVER_IP, PORT))
print("[*] Spoofer connected to sender.")

# Receive Sender's Public Key
public_key = spoofer_socket.recv(2048)

# Generate AES Key
aes_key = get_random_bytes(16)  # Spoofer generates a random AES key (wrong key)

# Encrypt AES Key with Sender's Public Key
cipher_rsa = PKCS1_OAEP.new(RSA.import_key(public_key))
encrypted_aes_key = cipher_rsa.encrypt(aes_key)

# Send Encrypted AES Key
spoofer_socket.send(encrypted_aes_key)
print("[*] Spoofer has exchanged AES key (but it's incorrect).")

while True:
    # Receive packet size (4 bytes)
    packet_size_bytes = spoofer_socket.recv(4)
    if not packet_size_bytes:
        print("[!] Sender disconnected.")
        break

    packet_size = struct.unpack(">I", packet_size_bytes)[0]

    # Receive encrypted data
    data_packet = spoofer_socket.recv(packet_size)

    # Deserialize received packet
    nonce, tag, encrypted_frame = pickle.loads(data_packet)

    # Print partial received encrypted frame data
    print(f"[SPOOFER] Received Encrypted Frame (first 20 bytes): {encrypted_frame[:20]}")
    print(f"[SPOOFER] Nonce: {nonce.hex()} | Tag: {tag.hex()}")

    try:
        # Attempt to decrypt with wrong AES key
        cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
        decrypted_frame = cipher_aes.decrypt_and_verify(encrypted_frame, tag)

        # Convert bytes to image
        frame = np.frombuffer(decrypted_frame, dtype=np.uint8)
        frame = cv2.imdecode(frame, cv2.IMREAD_COLOR)

        # Show spoofed video (will be distorted due to wrong decryption)
        cv2.imshow("Spoofed Stream", frame)

    except ValueError:
        print("[❌] Spoofer failed to decrypt frame. Encrypted data is useless!")

    if cv2.waitKey(1) & 0xFF == ord('q'):
        break

# Cleanup
spoofer_socket.close()
cv2.destroyAllWindows()
print("[*] Spoofer disconnected.")
