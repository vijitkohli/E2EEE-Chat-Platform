E2EE Command-Line Chat Platform
📌 Project Overview
A minimal, command-line-based client-server chat application designed to demonstrate core cryptographic principles and the CIA triad (Confidentiality, Integrity, Availability). This platform ensures that messages are strictly end-to-end encrypted (E2EE), preventing even the server or underlying infrastructure from accessing plaintext contents.

🚀 Key Features

True End-to-End Encryption (E2EE): Cryptographic operations (key generation, encryption, and decryption) are handled entirely on the client side.

Hybrid Encryption Model: Utilizes AES-256 in GCM mode for symmetric message encryption and RSA-2048 for secure asymmetric key exchange.

Message Authentication & Integrity: Leverages AES-GCM's built-in authentication tags (128-bit) to detect tampering or ciphertext modification.

Zero-Knowledge Server: The server functions strictly as a message relay and public key exchange facilitator, completely blind to message contents and private keys.

🛠️ Technology Stack & Cryptography
Language: Python 
Asymmetric Encryption: RSA (2048-bit) 
Symmetric Encryption: AES-GCM (256-bit) 
Architecture: Client-Server Model 

🏗️ System Architecture & Data Flow
1. Key Generation & Exchange
Upon connection, each client locally generates an RSA key pair. The public key is transmitted to the server for distribution, while the private key remains exclusively on the client's device.

2. Message Encryption (Sender)
When User A sends a message to User B:

A random AES-256 session key is generated.
The plaintext is encrypted using AES-GCM, producing the ciphertext, a nonce, and an authentication tag.
The AES session key is encrypted using User B's RSA public key.
The combined payload is transmitted to the server.

3. Message Decryption (Recipient)
Upon receiving the payload:

User B decrypts the AES session key using their RSA private key.

The recovered AES key is used to verify the authentication tag and decrypt the ciphertext back into plaintext.

🛡️ Threat Model & Limitations
As an educational prototype focused on transmission security, the system acknowledges the following limitations:

No Forward Secrecy: If a client's RSA private key is compromised, all past messages encrypted with that key could be decrypted.
No Mutual Authentication: Public keys are accepted without digital signatures or trusted certificate authorities, leaving theoretical vulnerabilities to Man-in-the-Middle (MITM) attacks if the server is compromised.
Offline Messaging: Both users must be online simultaneously for the session key exchange and communication to occur.

💻 Usage & Demo
1. Start the Server:
python server.py

2. Start a Client:
python client.py
