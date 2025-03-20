# E2E-Livestream
Cryptography course project that focuses on encryption of livestream to avoid middle-man attacks
Uses features such as RSA and AES to ensure secure and encrypted connection between server and client


# 🚀 Prototype-1: Breaking the Encryption
In this version, we will demonstrate a flawed encryption setup where a spoofer successfully decrypts the video stream. This will highlight a security vulnerability that forces us to move to Prototype-2 for a fix.

## 📌 Key Components of Prototype-1
✅ Sender (Legitimate streamer)
Uses RSA key exchange to share an AES key with the receiver.
Encrypts video frames using AES before sending.
✅ Receiver (Legitimate viewer)
Receives encrypted frames and decrypts them correctly using the AES key.
❌ Spoofer (Attacker)
Intercepts the AES key and uses it to decrypt the stream.
This shows that our current key exchange is flawed, making it necessary to implement a fix in Prototype-2.
📌 How Will the Spoofer Break the Encryption?
Intercept the AES Key 🔑

The AES key is exchanged without verifying the receiver.
Since the spoofer can also request the AES key, they get full access.
Decrypt the Video Frames 🎥

Since the spoofer now has the same AES key as the receiver, it can decrypt the video just like the legitimate receiver.
The spoofer can now see the clear-text video, breaking confidentiality.
📌 Implementation Steps
1️⃣ Modify the Sender
Allow multiple clients to connect.
The sender sends the AES key to all connected clients, including the attacker.
2️⃣ Modify the Spoofer
Connect to the sender as a normal receiver.
Receive the AES key and decrypt video frames just like a legitimate client.
🚨 Expected Outcome
Legitimate receiver sees the proper decrypted video.
Spoofer also sees the proper decrypted video, proving that security is compromised.


# 🛠 Moving to Prototype-2: Securing Against Unauthorized Access 🚀
🔴 Issue in Prototype-1:
The spoofer could still connect and receive encrypted frames.
Even though the spoofer couldn’t decrypt, an attacker with brute-force or stolen keys could still attempt to decrypt later.
No authentication step before sending video data.
# ✅ Prototype-2: Secure RSA-Based Authentication
🔐 What We Will Implement:
1️⃣ Authentication using RSA Signature

The sender will sign a challenge using its private key.
The receiver must verify the signature using the sender's public key.
Spoofers without the private key cannot authenticate!
2️⃣ Reject Unauthorized Clients

If the client fails verification, the connection is dropped before streaming begins.
🔧 Implementation Plan
We need to modify both sender and receiver:

🟢 Changes in sender.py
✅ Generate an RSA signature for authentication.
✅ Send a random challenge and expect a valid response.
✅ Reject unauthorized receivers before streaming starts.

🟢 Changes in receiver.py
✅ Receive the challenge and its signature.
✅ Verify the signature using the sender's public key.
✅ Proceed only if authentication passes.

