import socket
from aes_helper import encrypt_message, decrypt_message  # Import AES functions

HOST = '127.0.0.1'
PORT = 12345

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((HOST, PORT))

print("Connected to the server. Type 'bye' to exit.")

while True:
    # Get user input and encrypt it
    message = input("You: ")
    encrypted_message = encrypt_message(message)
    client_socket.sendall(encrypted_message)

    if message.lower() == "bye":
        print("Disconnected from server.")
        break

    # Receive encrypted response from server
    encrypted_data = client_socket.recv(1024)
    
    print(f"Received encrypted: {encrypted_data.hex()}")  # Print encrypted message

    # Decrypt and print message
    decrypted_message = decrypt_message(encrypted_data).decode()
    print(f"Server: {decrypted_message}")

client_socket.close()
