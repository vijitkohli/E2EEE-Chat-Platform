# server.py

import socket
import threading

clients = {}      # username -> socket
public_keys = {}  # username -> public key bytes

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

def handle_client(client_socket):
    username = ""
    try:
        username_len_bytes = recv_all(client_socket, 4)
        if not username_len_bytes: return
        username_len = int.from_bytes(username_len_bytes, 'big')
        username = recv_all(client_socket, username_len).decode('utf-8')

        key_len_bytes = recv_all(client_socket, 4)
        key_len = int.from_bytes(key_len_bytes, 'big')
        public_key_bytes = recv_all(client_socket, key_len)

        public_keys[username] = public_key_bytes
        clients[username] = client_socket
        print(f"{username} connected and public key stored.")

        while True:
            # This first read is now always a request from the client
            req_len_bytes = recv_all(client_socket, 4)
            if not req_len_bytes: break
            req_len = int.from_bytes(req_len_bytes, 'big')
            request = recv_all(client_socket, req_len).decode('utf-8')

            # Handle public key request
            if request.startswith("GETKEY "):
                target_user = request[7:]
                target_socket = client_socket # Send response to the requester
                print("\n" + "=" * 60)
                print(f"[E2EE Chat Server] Public Key Request")
                print(f"Requester : {username}")
                print(f"Target    : {target_user}")
                if target_user in public_keys:
                    print("Status    : Key Found and Sent")
                else:
                    print("Status    : Key Not Found")
                print("=" * 60 + "\n")


                # --- PROTOCOL CHANGE: Respond with a 'KEY' header ---
                header = b'KEY'
                target_socket.sendall(len(header).to_bytes(4, 'big'))
                target_socket.sendall(header)

                if target_user in public_keys:
                    key_bytes = public_keys[target_user]
                    target_socket.sendall(len(key_bytes).to_bytes(4, 'big'))
                    target_socket.sendall(key_bytes)
                else:
                    target_socket.sendall((0).to_bytes(4, 'big')) # Length 0 means not found
                continue

            # Handle message forwarding
            if request.startswith("SENDMSG "):
                target_user = request[8:]
                
                msg_len_bytes = recv_all(client_socket, 4)
                msg_len = int.from_bytes(msg_len_bytes, 'big')
                encrypted_msg = recv_all(client_socket, msg_len)
                # Log what server sees
                print("\n" + "=" * 60)
                print(f"[E2EE Chat Server] Message Forwarding Log")
                print(f"From      : {username}")
                print(f"To        : {target_user}")
                print(f"Size      : {len(encrypted_msg)} bytes")
                print("-" * 60)
                print("Raw Ciphertext (bytes):")
                print(f"{repr(encrypted_msg)}")
                print("-" * 60)
                print("Ciphertext (hex):")
                # Group hex in readable chunks (e.g., 32 bytes per line)
                hex_str = encrypted_msg.hex()
                for i in range(0, len(hex_str), 64):
                    print(hex_str[i:i+64])
                print("=" * 60 + "\n")

                if target_user in clients:
                    target_socket = clients[target_user]
                    sender_username = username.encode('utf-8')

                    # --- PROTOCOL CHANGE: Forward with a 'MSG' header ---
                    header = b'MSG'
                    target_socket.sendall(len(header).to_bytes(4, 'big'))
                    target_socket.sendall(header)
                    
                    # Now send sender and message
                    target_socket.sendall(len(sender_username).to_bytes(4, 'big'))
                    target_socket.sendall(sender_username)
                    target_socket.sendall(msg_len_bytes)
                    target_socket.sendall(encrypted_msg)
                    print(f"Forwarded message from {username} to {target_user}")
                else:
                    print(f"User {target_user} not connected. Message from {username} dropped.")

    except Exception as e:
        print(f"Client error ({username}): {e}")
    finally:
        if username and username in clients:
            del clients[username]
            del public_keys[username]
            print(f"{username} disconnected.")
        client_socket.close()

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', 5555))
    server.listen(5)
    print("Server listening on port 5555")

    while True:
        client_sock, addr = server.accept()
        threading.Thread(target=handle_client, args=(client_sock,), daemon=True).start()

if __name__ == "__main__":
    main()