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

def recv_exact(sock, size):
    """Receive exactly 'size' bytes from the socket."""
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            return None
        data += chunk
    return data

SERVER_IP = "127.0.0.1"
PORT = 5000

print("[*] Connecting to sender...")
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((SERVER_IP, PORT))
print("[✅] Connected to sender!")

# Step 1: Receive sender's public key
sender_public_key = client_socket.recv(2048)
print("[🔑] Received sender's public key.")

# Step 2: Generate receiver's RSA key pair dynamically
receiver_rsa_key = RSA.generate(2048)
receiver_private_key = receiver_rsa_key.export_key()
receiver_public_key = receiver_rsa_key.publickey().export_key()
print("[🔑] Receiver's key pair generated.")

# Step 3: Receive authentication challenge
challenge_data = client_socket.recv(4096)
challenge, signature = pickle.loads(challenge_data)

# Step 4: Verify sender's signature
challenge_hash = SHA256.new(challenge)
try:
    pkcs1_15.new(RSA.import_key(sender_public_key)).verify(challenge_hash, signature)
    print("[✅] Sender authentication successful!")
    client_socket.send(b'1')  # Send success signal
except (ValueError, TypeError):
    print("[❌] Sender authentication failed!")
    client_socket.send(b'0')  # Send failure signal
    client_socket.close()
    exit()

# Step 5: Send receiver's public key to sender
client_socket.send(receiver_public_key)
print("[🔑] Sent receiver's public key to sender.")

# Step 6: Receive AES key
encrypted_aes_key = client_socket.recv(256)
cipher_rsa = PKCS1_OAEP.new(RSA.import_key(receiver_private_key))
aes_key = cipher_rsa.decrypt(encrypted_aes_key)  # ✅ Correct decryption with private key

print("[✅] AES Key received! Ready to receive video stream.")

try:
    while True:
        packet_size_bytes = recv_exact(client_socket, 4)
        if not packet_size_bytes:
            break

        packet_size = struct.unpack(">I", packet_size_bytes)[0]
        data_packet = recv_exact(client_socket, packet_size)
        if not data_packet:
            break

        nonce, tag, encrypted_frame = pickle.loads(data_packet)

        # Decrypt the frame
        cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
        decrypted_frame = cipher_aes.decrypt_and_verify(encrypted_frame, tag)

        frame = np.frombuffer(decrypted_frame, dtype=np.uint8)
        frame = cv2.imdecode(frame, cv2.IMREAD_COLOR)

        cv2.imshow("Decrypted Video Stream", frame)

        if cv2.waitKey(1) & 0xFF == ord('q'):
            break

except Exception as e:
    print(f"[❌] Error: {e}")

finally:
    client_socket.close()
    cv2.destroyAllWindows()
    print("[*] Stream stopped.")
