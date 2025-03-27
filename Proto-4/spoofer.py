import socket
import pickle
import struct
import cv2
import numpy as np
import time
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

# Spoofer Configuration (Update SERVER_IP if running on another device)
SERVER_IP = "127.0.0.1"  # Change to sender's IP if needed
PORT = 5000

def reliable_recv(sock, size):
    """Ensure the full 'size' bytes are received before returning."""
    data = b''
    while len(data) < size:
        packet = sock.recv(size - len(data))
        if not packet:
            return None
        data += packet
    return data

while True:
    try:
        print("\n[*] Spoofer trying to connect...")
        spoofer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        spoofer_socket.settimeout(10)  # Prevents infinite waiting
        spoofer_socket.connect((SERVER_IP, PORT))
        print("[✔] Connected to sender!")

        # Receive Sender's Public Key
        public_key = spoofer_socket.recv(2048)
        if not public_key:
            print("[!] Failed to receive public key. Retrying...")
            spoofer_socket.close()
            time.sleep(5)
            continue

        print(f"[✔] Received public key ({len(public_key)} bytes)")

        # Generate a WRONG AES Key (Incorrect on purpose)
        wrong_aes_key = get_random_bytes(16)

        # Encrypt AES Key with Sender's Public Key
        cipher_rsa = PKCS1_OAEP.new(RSA.import_key(public_key))
        encrypted_aes_key = cipher_rsa.encrypt(wrong_aes_key)

        # Send Encrypted AES Key
        spoofer_socket.send(encrypted_aes_key)
        print("[⚠] Spoofer sent an incorrect AES key!")

        while True:
            # Receive 4-byte packet size
            packet_size_bytes = reliable_recv(spoofer_socket, 4)
            if not packet_size_bytes:
                print("[!] Sender closed the connection or no packet size received.")
                break

            packet_size = struct.unpack(">I", packet_size_bytes)[0]  # Big-endian integer
            print(f"[✔] Packet size received: {packet_size} bytes")

            # Receive the full data packet
            data_packet = reliable_recv(spoofer_socket, packet_size)
            if data_packet is None:
                print("[!] Failed to receive full data packet. Breaking...")
                break

            try:
                # Attempt to deserialize the packet
                nonce, tag, encrypted_frame, frame_hash = pickle.loads(data_packet)
                print(f"[✔] Received encrypted frame (Size: {len(encrypted_frame)} bytes)")

                # Convert encrypted frame bytes into a NumPy array
                encrypted_frame_array = np.frombuffer(encrypted_frame, dtype=np.uint8)

                # Try decoding (will fail since decryption is incorrect)
                encrypted_image = cv2.imdecode(encrypted_frame_array, cv2.IMREAD_COLOR)

                # If decoding fails, display random noise
                if encrypted_image is None:
                    print("[❌] Failed to decode image! Displaying random noise...")
                    encrypted_image = np.random.randint(0, 256, (480, 640, 3), dtype=np.uint8)

                cv2.imshow("Spoofed Stream (Encrypted / Garbled)", encrypted_image)

            except (pickle.UnpicklingError, EOFError) as e:
                print(f"[❌] Corrupted packet or failed to unpack: {e}")
                encrypted_image = np.random.randint(0, 256, (480, 640, 3), dtype=np.uint8)
                cv2.imshow("Spoofed Stream (Corrupted Data)", encrypted_image)

            if cv2.waitKey(1) & 0xFF == ord('q'):
                print("[*] Exiting spoofed stream...")
                raise KeyboardInterrupt  # Exit both loops cleanly

    except (ConnectionResetError, ConnectionAbortedError, socket.timeout):
        print("[!] Connection lost. Retrying in 5 seconds...")
        time.sleep(5)

    except KeyboardInterrupt:
        print("[*] Spoofer manually stopped.")
        break

    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        time.sleep(5)

    finally:
        try:
            spoofer_socket.close()
        except:
            pass
        cv2.destroyAllWindows()

print("[*] Spoofer disconnected cleanly.")
