import socket
import cv2
import numpy as np
import pickle
import struct
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

# Function to receive an exact number of bytes
def recv_exact(sock, size):
    """Receive exactly 'size' bytes from the socket."""
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            return None
        data += chunk
    return data

def start_receive():
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

    # Step 3: Generate AES key and encrypt it using sender's public key
    aes_key = get_random_bytes(16)
    cipher_rsa = PKCS1_OAEP.new(RSA.import_key(sender_public_key))
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)

    # Step 4: Send encrypted AES key to sender
    client_socket.send(encrypted_aes_key)
    print("[🔐] AES key securely sent to sender.")

    print("[✅] AES Key exchange successful! Ready to receive video stream.")

    try:
        while True:
            # Step 5: Receive the length of the data packet
            packet_size_bytes = recv_exact(client_socket, 4)
            if not packet_size_bytes:
                print("[❌] Disconnected from sender.")
                break

            packet_size = struct.unpack(">I", packet_size_bytes)[0]

            # Step 6: Receive full encrypted packet
            data_packet = recv_exact(client_socket, packet_size)
            if not data_packet:
                print("[❌] Lost connection or incomplete frame.")
                break

            try:
                # Deserialize received packet
                nonce, tag, encrypted_frame = pickle.loads(data_packet)

                # Display encrypted frame data for debugging
                print(f"[📦] Received Encrypted Frame (Size: {len(encrypted_frame)} bytes)")

                # Step 7: Decrypt the frame
                cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
                decrypted_frame = cipher_aes.decrypt_and_verify(encrypted_frame, tag)

                # Convert bytes to frame
                frame = np.frombuffer(decrypted_frame, dtype=np.uint8)
                frame = cv2.imdecode(frame, cv2.IMREAD_COLOR)

                if frame is None:
                    print("[❌] Decoding failed. Skipping frame.")
                    continue

                # Display the decrypted frame
                cv2.imshow("Decrypted Video Stream", frame)

                # Press 'q' to quit
                if cv2.waitKey(1) & 0xFF == ord('q'):
                    break

            except Exception as e:
                print(f"[❌] Error processing frame: {e}")
                continue

    except Exception as e:
        print(f"[❌] Error: {e}")

    finally:
        client_socket.close()
        cv2.destroyAllWindows()
        print("[*] Stream stopped.")

# Start receiver
if __name__ == "__main__":
    start_receive()
