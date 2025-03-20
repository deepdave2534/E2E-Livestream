from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os

# AES key (Must be 16, 24, or 32 bytes long)
SECRET_KEY = b'Sixteen byte key'  # Ensure this is securely shared between server & client

def encrypt_message(message):
    """Encrypt message using AES-GCM."""
    nonce = os.urandom(12)  # Generate a new nonce (12 bytes)
    cipher = Cipher(algorithms.AES(SECRET_KEY), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    return nonce + encryptor.tag + ciphertext  # Send nonce, tag, and ciphertext together

def decrypt_message(encrypted_data):
    """Decrypt message using AES-GCM."""
    nonce = encrypted_data[:12]  # Extract nonce
    tag = encrypted_data[12:28]  # Extract tag
    ciphertext = encrypted_data[28:]  # Extract ciphertext

    cipher = Cipher(algorithms.AES(SECRET_KEY), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()
