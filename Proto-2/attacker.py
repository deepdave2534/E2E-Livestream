import socket
import pickle
import struct
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15

SERVER_IP = "127.0.0.1"
PORT = 5000

print("[*] Attacker trying to connect to sender...")
attacker_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
attacker_socket.connect((SERVER_IP, PORT))
print("[✅] Connected to sender!")

# Step 1: Receive sender's public key
sender_public_key = attacker_socket.recv(2048)
print("[🔑] Received sender's public key.")

# Step 2: Generate fake RSA key pair
fake_rsa_key = RSA.generate(2048)
fake_private_key = fake_rsa_key.export_key()
fake_public_key = fake_rsa_key.publickey().export_key()
print("[🔑] Attacker generated a fake RSA key pair.")

# Step 3: Receive authentication challenge from sender
challenge_data = attacker_socket.recv(4096)
challenge, signature = pickle.loads(challenge_data)

# Step 4: Try to verify sender's signature (but attacker doesn't have sender's private key)
challenge_hash = SHA256.new(challenge)
try:
    pkcs1_15.new(RSA.import_key(sender_public_key)).verify(challenge_hash, signature)
    print("[✅] Authentication successful! (Fake, but sender won't detect yet)")
    attacker_socket.send(b'1')  # Tries to fool sender
except (ValueError, TypeError):
    print("[❌] Authentication failed! Sender will reject me.")
    attacker_socket.send(b'0')  # Honest failure
    attacker_socket.close()
    exit()

# Step 5: Send fake public key to sender
attacker_socket.send(fake_public_key)
print("[🔑] Attacker sent a fake public key to sender.")

# Step 6: Try to receive AES key
encrypted_aes_key = attacker_socket.recv(256)
cipher_rsa = PKCS1_OAEP.new(RSA.import_key(fake_private_key))

try:
    aes_key = cipher_rsa.decrypt(encrypted_aes_key)
    print("[🔑] Attacker successfully decrypted AES key! (This should NOT happen!)")
except ValueError:
    print("[❌] Decryption failed! AES key is protected.")
    attacker_socket.close()
    exit()

# Step 7: Try to receive video stream (but fails)
try:
    while True:
        packet_size_bytes = attacker_socket.recv(4)
        if not packet_size_bytes:
            break

        packet_size = struct.unpack(">I", packet_size_bytes)[0]
        data_packet = attacker_socket.recv(packet_size)

        if not data_packet:
            break

        print("[❌] Attacker cannot decrypt the video stream!")

except Exception as e:
    print(f"[❌] Error: {e}")

finally:
    attacker_socket.close()
    print("[*] Attacker disconnected.")
