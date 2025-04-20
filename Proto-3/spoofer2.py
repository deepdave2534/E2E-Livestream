import socket
import pickle
import struct
import cv2
import numpy as np
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

# Spoofer Configuration (Same as legitimate receiver)
SERVER_IP = "192.168.82.135"  # Change to sender's actual IP
PORT = 5000

# Attempt to connect to the sender
print("[*] Spoofer trying to connect...")
spoofer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
spoofer_socket.connect((SERVER_IP, PORT))

print("[!] Connected to sender (as a spoofer)")

# Receive Sender's Public Key
public_key = spoofer_socket.recv(2048)

# Generate an INCORRECT AES Key (Different from what the sender expects)
wrong_aes_key = get_random_bytes(16)

# Encrypt AES Key with Sender's Public Key (Spoofer does this correctly)
cipher_rsa = PKCS1_OAEP.new(RSA.import_key(public_key))
encrypted_aes_key = cipher_rsa.encrypt(wrong_aes_key)

# Send Encrypted AES Key
spoofer_socket.send(encrypted_aes_key)

print("[⚠] Spoofer successfully exchanged an AES key, but it's incorrect!")

try:
    while True:
        # Receive packet size (4 bytes)
        packet_size_bytes = spoofer_socket.recv(4)
        if not packet_size_bytes:
            print("[!] Sender closed connection.")
            break

        packet_size = struct.unpack(">I", packet_size_bytes)[0]  # Unpack as big-endian integer

        # Receive full encrypted data packet
        data_packet = spoofer_socket.recv(packet_size)
        if not data_packet:
            print("[!] No data received. Connection lost.")
            break

        try:
            # Deserialize received packet
            nonce, tag, encrypted_frame = pickle.loads(data_packet)

            # Convert encrypted frame bytes into a NumPy array
            encrypted_frame_array = np.frombuffer(encrypted_frame, dtype=np.uint8)

            # Try to display encrypted data as an image (garbled data)
            encrypted_image = cv2.imdecode(encrypted_frame_array, cv2.IMREAD_COLOR)

            # If decoding fails, generate a random noise image
            if encrypted_image is None:
                encrypted_image = np.random.randint(0, 256, (480, 640, 3), dtype=np.uint8)

            cv2.imshow("Spoofed Stream (Encrypted Data)", encrypted_image)

        except pickle.UnpicklingError:
            print("[❌] Data packet corruption detected.")

        if cv2.waitKey(1) & 0xFF == ord('q'):
            break

except Exception as e:
    print(f"[!] Error: {e}")

finally:
    spoofer_socket.close()
    cv2.destroyAllWindows()
    print("[*] Spoofer disconnected.")
