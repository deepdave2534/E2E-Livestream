import socket
from aes_helper import encrypt_message, decrypt_message  # Import AES functions

HOST = '127.0.0.1'
PORT = 12345

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen(1)  # Accept one client

print(f"Server listening on {HOST}:{PORT}")
client_socket, client_address = server_socket.accept()
print(f"Connected by {client_address}")

while True:
    # Receive encrypted data from client
    encrypted_data = client_socket.recv(1024)
    if not encrypted_data:
        break
    
    print(f"Received encrypted: {encrypted_data.hex()}")  # Print encrypted message

    # Decrypt message
    decrypted_message = decrypt_message(encrypted_data).decode()
    print(f"Client: {decrypted_message}")

    if decrypted_message.lower() == "bye":
        print("Client disconnected.")
        break

    # Get input from server
    message = input("You: ")

    # Encrypt and send to client
    encrypted_message = encrypt_message(message)
    client_socket.sendall(encrypted_message)

client_socket.close()
server_socket.close()
