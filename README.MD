End-to-End Encrypted Chat (E2EE Chat)
This project is a simple proof-of-concept end-to-end encrypted chat system. It allows two users to communicate securely via a central server. Messages are encrypted client-side using AES-GCM, and AES keys are encrypted using RSA. The server cannot read any message contents.

Features
RSA key pair generation per client

Public key exchange through the server

AES-GCM encryption for message confidentiality and integrity

End-to-end encryption with no plaintext exposed to the server

Logged server output showing only ciphertext

How It Works
Clients generate RSA key pairs.

Public keys are sent to the server and shared on request.

Messages are encrypted with AES; AES keys are encrypted with the recipient’s public RSA key.

The server only forwards encrypted blobs and cannot decrypt them.

Requirements
Python 3.8+

cryptography library (pip install cryptography)

Running the Project
Start the server:
python server.py

Start atleast two clients in a separate terminals each:
python client.py

Follow the prompts to send encrypted messages.

Purpose
This was built to demonstrate understanding of secure messaging using real cryptographic techniques, with emphasis on the CIA triad.

