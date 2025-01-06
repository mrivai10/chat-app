import socket
import threading
import json
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

class ChatServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.clients = {}  
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.lock = threading.Lock()
        
    def start(self):
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        print(f"Server berjalan di {self.host}:{self.port}")
        
        while True:
            client_socket, _ = self.server_socket.accept()
            threading.Thread(target=self.handle_client, args=(client_socket,)).start()

    def handle_client(self, client_socket):
        try:
            # Terima username dan public key dari client
            client_data = client_socket.recv(4096)
            client_info = json.loads(client_data.decode())
            username = client_info['username']
            client_public_key_pem = client_info['public_key']
            
            with self.lock:
                # Simpan informasi client
                self.clients[username] = {
                    'socket': client_socket,
                    'public_key_pem': client_public_key_pem
                }
                
                # Kirim daftar user yang online beserta public key mereka
                self.broadcast_online_users()
            
            print(f"User {username} terhubung")
            
            while True:
                try:
                    # Terima pesan dari client
                    message_data = client_socket.recv(4096)
                    if not message_data:
                        break
                    
                    message_info = json.loads(message_data.decode())
                    target_user = message_info['to']
                    encrypted_message = message_info['message']
                    
                    # Forward pesan ke target user
                    if target_user in self.clients:
                        target_socket = self.clients[target_user]['socket']
                        forwarded_message = {
                            'from': username,
                            'message': encrypted_message
                        }
                        target_socket.send(json.dumps(forwarded_message).encode())
                        print(f"Pesan dari {username} diteruskan ke {target_user}")
                    
                except Exception as e:
                    print(f"Error dalam handle_client loop: {e}")
                    break
                    
        except Exception as e:
            print(f"Error dalam handle_client: {e}")
        finally:
            with self.lock:
                if username in self.clients:
                    print(f"User {username} terputus")
                    del self.clients[username]
                    self.broadcast_online_users()
            client_socket.close()

    def broadcast_online_users(self):
        users_data = {}
        for username, data in self.clients.items():
            users_data[username] = {
                'public_key': data['public_key_pem']
            }
            
        for username, data in self.clients.items():
            try:
                message = {
                    'type': 'online_users',
                    'users': {
                        user: udata 
                        for user, udata in users_data.items() 
                        if user != username
                    }
                }
                data['socket'].send(json.dumps(message).encode())
            except Exception as e:
                print(f"Error broadcasting to {username}: {e}")
                continue

if __name__ == "__main__":
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    server = ChatServer(local_ip, 12345)
    server.start()