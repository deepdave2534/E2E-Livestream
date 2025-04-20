import socket
import threading
import pickle
import struct
import cv2
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256, HMAC
from Crypto.Signature import pkcs1_15

SERVER_IP = "0.0.0.0"  # Listen on all network interfaces
PORT = 5000

# Generate RSA key pair
rsa_key = RSA.generate(2048)
private_key = rsa_key.export_key()
public_key = rsa_key.publickey().export_key()
print("[🔑] RSA key pair generated.")

# Function to handle each client
def handle_client(conn, addr):
    print(f"[*] Connected to {addr}")

    try:
        # Step 1: Send public key
        conn.sendall(public_key)

        # Step 2: Authentication challenge
        challenge = get_random_bytes(32)
        challenge_hash = SHA256.new(challenge)
        signature = pkcs1_15.new(rsa_key).sign(challenge_hash)
        conn.sendall(pickle.dumps((challenge, signature)))

        # Step 3: Receive authentication result
        auth_result = conn.recv(1)
        if auth_result != b'1':
            print(f"[❌] Authentication failed for {addr}! (Possibly an attacker)")
            conn.sendall(b'0')
            return
        else:
            print(f"[✅] Authentication successful for {addr}!")
            conn.sendall(b'1')

        # Step 4: Receive client's public key
        receiver_public_key = conn.recv(4096)
        receiver_rsa_key = RSA.import_key(receiver_public_key)

        # Step 5: Generate AES Key & Encrypt it
        aes_key = get_random_bytes(16)
        cipher_rsa = PKCS1_OAEP.new(receiver_rsa_key)
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)
        conn.sendall(encrypted_aes_key)

        print(f"[✅] Secure AES key sent to {addr}!")

        # Step 6: Start video streaming
        cap = cv2.VideoCapture(0)
        if not cap.isOpened():
            print("[❌] Error: Cannot access webcam!")
            return

        while cap.isOpened():
            ret, frame = cap.read()
            if not ret:
                print("[❌] No frame captured, stopping stream.")
                break

            _, buffer = cv2.imencode('.jpg', frame)
            frame_bytes = buffer.tobytes()

            # Encrypt frame with AES
            cipher_aes = AES.new(aes_key, AES.MODE_EAX)
            nonce = cipher_aes.nonce
            encrypted_frame, tag = cipher_aes.encrypt_and_digest(frame_bytes)

            # Generate HMAC for integrity
            hmac = HMAC.new(aes_key, digestmod=SHA256)
            hmac.update(encrypted_frame)
            hmac_value = hmac.digest()

            # Send (Nonce + Tag + Encrypted Frame + HMAC)
            data_packet = pickle.dumps((nonce, tag, encrypted_frame, hmac_value))
            conn.sendall(struct.pack(">I", len(data_packet)))  # Send size
            conn.sendall(data_packet)

    except Exception as e:
        print(f"[❌] Error with {addr}: {e}")

    finally:
        print(f"[*] Closing connection with {addr}")
        conn.close()

# Main function
def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((SERVER_IP, PORT))
    server_socket.listen(5)
    print(f"[*] Server listening on {SERVER_IP}:{PORT}")

    while True:
        conn, addr = server_socket.accept()
        client_thread = threading.Thread(target=handle_client, args=(conn, addr))
        client_thread.start()

if __name__ == "__main__":
    main()
