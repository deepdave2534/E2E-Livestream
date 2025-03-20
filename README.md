# E2E-Livestream  

Cryptography course project that focuses on encryption of livestreams to prevent middle-man attacks.  
Uses RSA and AES encryption to ensure a secure connection between the server and client.  

---  

## Prototype-1: Breaking the Encryption  

This version demonstrates a flawed encryption setup where an attacker (spoofer) successfully decrypts the video stream. This highlights a security vulnerability that will be fixed in Prototype-2.  

### Key Components  

**Sender (Legitimate streamer)**  
- Uses RSA key exchange to share an AES key with the receiver.  
- Encrypts video frames using AES before sending.  

**Receiver (Legitimate viewer)**  
- Receives encrypted frames and decrypts them correctly using the AES key.  

**Spoofer (Attacker)**  
- Intercepts the AES key and uses it to decrypt the stream.  
- This proves the key exchange is flawed, necessitating a fix in Prototype-2.  

---  

### How Will the Spoofer Break the Encryption?  

#### Intercepting the AES Key  

- The AES key is exchanged without verifying the receiver.  
- Any client, including the spoofer, can request and obtain the key.  

#### Decrypting the Video Frames  

- Since the spoofer has the same AES key as the receiver, they can decrypt the video just like a legitimate user.  
- This results in a loss of confidentiality.  

---  

### Implementation Steps  

1. **Modify the Sender**  
   - Allow multiple clients to connect.  
   - The sender distributes the AES key to all connected clients, including the attacker.  

2. **Modify the Spoofer**  
   - Connect to the sender as a normal receiver.  
   - Receive the AES key and decrypt video frames like a legitimate client.  

#### Expected Outcome  

- The legitimate receiver correctly decrypts the video.  
- The spoofer also decrypts the video, proving that security is compromised.  

---  

## Moving to Prototype-2: Securing Against Unauthorized Access  

### Issues in Prototype-1  

- The spoofer can still connect and receive encrypted frames.  
- Even if the spoofer does not decrypt immediately, an attacker with brute-force techniques or stolen keys can attempt to decrypt later.  
- No authentication step before sending video data.  

---  

## Prototype-2: Secure RSA-Based Authentication  

### What Will Be Implemented  

1. **Authentication Using RSA Signatures**  
   - The sender signs a challenge using its private key.  
   - The receiver must verify the signature using the sender's public key.  
   - Spoofers without the private key cannot authenticate.  

2. **Rejecting Unauthorized Clients**  
   - If a client fails verification, the connection is dropped before streaming begins.  

---  

### Implementation Plan  

#### Changes in `sender.py`  
- Generate an RSA signature for authentication.  
- Send a random challenge and expect a valid response.  
- Reject unauthorized receivers before streaming starts.  

#### Changes in `receiver.py`  
- Receive the challenge and its signature.  
- Verify the signature using the sender's public key.  
- Proceed only if authentication is successful.  
