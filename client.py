# client.py

import socket
import threading
from cryptography.hazmat.primitives import serialization
from crypto_utils import * 

# An Event to signal that a key has been received
key_received_event = threading.Event()
# A shared variable to hold the key
received_key = None

def send_all(sock, data):
    total_sent = 0
    while total_sent < len(data):
        sent = sock.send(data[total_sent:])
        if sent == 0:
            raise RuntimeError("Socket connection broken")
        total_sent += sent

def recv_all(sock, length):
    data = b''
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            break
        data += chunk
    return data

def load_keys(username):
    priv_path = f"{username}_private_key.pem"
    pub_path = f"{username}_public_key.pem"
    import os
    from cryptography.hazmat.primitives.asymmetric import rsa

    if not os.path.exists(priv_path) or not os.path.exists(pub_path):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with open(priv_path, "wb") as f: f.write(private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()))
        public_key = private_key.public_key()
        with open(pub_path, "wb") as f: f.write(public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo))
    else:
        with open(priv_path, "rb") as f: private_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(pub_path, "rb") as f: public_key = serialization.load_pem_public_key(f.read())
    return private_key, public_key

def receive_messages(sock, private_key):
    global received_key
    while True:
        try:
            # Read header to determine message type
            header_len_bytes = recv_all(sock, 4)
            if not header_len_bytes: break
            header_len = int.from_bytes(header_len_bytes, 'big')
            header = recv_all(sock, header_len).decode('utf-8')

            if header == 'MSG':
                print("\n======[ Incoming Encrypted Message ]======")
                # Read sender username
                sender_len = int.from_bytes(recv_all(sock, 4), 'big')
                sender = recv_all(sock, sender_len).decode('utf-8')
                
                msg_len = int.from_bytes(recv_all(sock, 4), 'big')
                data = recv_all(sock, msg_len)

                print(f"[From] {sender}")
                print(f"[Total Encrypted Payload Size] {len(data)} bytes")
                
                encrypted_key = data[:256]
                nonce = data[256:256+12]
                tag = data[256+12:256+12+16]
                ciphertext = data[256+12+16:]

                print("\n[Step 1] Received RSA-encrypted AES key:")
                print(f"Encrypted AES key (256 bytes): {encrypted_key.hex()[:64]}...")

                # Decrypt AES key using RSA
                aes_key = decrypt_key_rsa(encrypted_key, private_key)
                print("[Step 2] Decrypted AES session key using private RSA key.")

                print("\n[Step 3] AES-GCM components:")
                print(f"Nonce (12 bytes): {nonce.hex()}")
                print(f"Tag   (16 bytes): {tag.hex()}")
                print(f"Ciphertext ({len(ciphertext)} bytes): {ciphertext.hex()[:64]}...")

                # Decrypt the actual message
                plaintext = decrypt_message(ciphertext, nonce, tag, aes_key)

                print("\n[Step 4] Decryption successful.")
                print(f"[Plaintext Message] \"{plaintext}\"\n")
                print("===========================================\n")

                print("Send message to: ", end="", flush=True)

            elif header == 'KEY':
                key_len = int.from_bytes(recv_all(sock, 4), 'big')
                if key_len == 0:
                    received_key = None
                else:
                    key_bytes = recv_all(sock, key_len)
                    received_key = serialization.load_pem_public_key(key_bytes)
                
                key_received_event.set()

        except (ConnectionError, BrokenPipeError):
            print("\n[CONNECTION ERROR] Connection lost.")
            break
        except Exception as e:
            print(f"\n[RECEIVE ERROR] {e}")
            break

def request_public_key(sock, recipient):
    global received_key
    
    # Clear the event from any previous calls
    key_received_event.clear()

    # Send the request
    request = f"GETKEY {recipient}".encode('utf-8')
    sock.sendall(len(request).to_bytes(4, 'big'))
    sock.sendall(request)

    # Wait for the receiver thread to signal that the key is ready (with a timeout)
    # The timeout is crucial to prevent waiting forever
    was_set = key_received_event.wait(timeout=5.0) 
    
    if not was_set:
        print("Timeout: Did not receive public key from server.")
        return None
    
    return received_key

def main():
    server_ip = '127.0.0.1'
    server_port = 5555
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((server_ip, server_port))
    except ConnectionRefusedError:
        print("Connection refused. Is the server running?")
        return

    username = input("Enter your username: ")
    private_key, public_key = load_keys(username)

    # Initial registration (no response expected, so no need to wait)
    username_bytes = username.encode('utf-8')
    sock.sendall(len(username_bytes).to_bytes(4, 'big'))
    sock.sendall(username_bytes)
    pub_bytes = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    sock.sendall(len(pub_bytes).to_bytes(4, 'big'))
    send_all(sock, pub_bytes)

    # Start the one and only receiver thread
    threading.Thread(target=receive_messages, args=(sock, private_key), daemon=True).start()

    while True:
        try:
            recipient = input("Send message to: ").strip()
            if not recipient: continue
            
            # Use the new request/wait mechanism
            recipient_pub = request_public_key(sock, recipient)
            if recipient_pub is None:
                print(f"Could not get public key for '{recipient}'.")
                continue

            message = input("Message: ").strip()
            if not message: continue
            
            aes_key = generate_aes_key()
            ciphertext, nonce, tag = encrypt_message(message, aes_key)
            encrypted_aes_key = encrypt_key_rsa(aes_key, recipient_pub)
            full_message = encrypted_aes_key + nonce + tag + ciphertext

            # Send message request
            request = f"SENDMSG {recipient}".encode('utf-8')
            sock.sendall(len(request).to_bytes(4, 'big'))
            sock.sendall(request)
            
            sock.sendall(len(full_message).to_bytes(4, 'big'))
            send_all(sock, full_message)

            print("Message sent.")
        except KeyboardInterrupt:
            print("\nClosing client.")
            break
        except Exception as e:
            print(f"\nAn error occurred in main loop: {e}")
            break
    sock.close()


if __name__ == "__main__":
    main()