import socket
import pickle
import struct
import cv2
import numpy as np
from Crypto.Cipher import AES

# Spoofer Configuration (Same as legitimate receiver)
SERVER_IP = "127.0.0.1"  # Change to sender's actual IP
PORT = 5000

# Attempt to connect to the sender
print("[*] Spoofer trying to connect...")
spoofer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
spoofer_socket.connect((SERVER_IP, PORT))

print("[!] Connected to sender (as a spoofer), but without the correct RSA key.")

# Spoofer **DOES NOT** perform RSA key exchange.
# It will attempt to receive encrypted frames without having the AES key.

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

            print("[!] Spoofer received encrypted data but cannot decrypt it.")

            # **Spoofer does NOT have the AES key**, so it attempts to decrypt blindly
            try:
                cipher_aes = AES.new(b"wrong_key_123456", AES.MODE_EAX, nonce=nonce)  # Fake AES key
                decrypted_frame = cipher_aes.decrypt_and_verify(encrypted_frame, tag)

                # Convert bytes to frame
                frame = np.frombuffer(decrypted_frame, dtype=np.uint8)
                frame = cv2.imdecode(frame, cv2.IMREAD_COLOR)

                if frame is None:
                    raise ValueError("Frame decoding failed.")

                cv2.imshow("Spoofed Stream (Corrupted)", frame)

            except (ValueError, KeyError):
                print("[❌] Decryption failed! Spoofer cannot view the stream.")

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
