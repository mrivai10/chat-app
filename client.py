import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import socket
import threading
import json
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from datetime import datetime
import tkinter.font as tkfont 

class LoginWindow:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("Login")
        self.window.geometry("600x400")
        self.window.config(bg="#1a1f3d")

        self.font = tkfont.Font(family="Poppins", size=10)

        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)

        tk.Label(self.window, text="IP Server:", bg="#1a1f3d", fg="white", font=self.font).pack(pady=5)
        self.ip_entry = tk.Entry(self.window, font=self.font)
        self.ip_entry.insert(0, local_ip)
        self.ip_entry.config(state='disabled')
        self.ip_entry.pack(pady=5)

        tk.Label(self.window, text="Port:", bg="#1a1f3d", fg="white", font=self.font).pack(pady=5)
        self.port_entry = tk.Entry(self.window, font=self.font)
        self.port_entry.insert(0, "12345")
        self.port_entry.config(state='disabled')
        self.port_entry.pack(pady=5)

        tk.Label(self.window, text="Username:", bg="#1a1f3d", fg="white", font=self.font).pack(pady=5)
        self.username_entry = tk.Entry(self.window, font=self.font)
        self.username_entry.pack(pady=5)

        tk.Button(self.window, text="Masuk", bg="#7a6b1d", fg="white", font=self.font, command=self.login).pack(pady=20)

        self.result = None

    def login(self):
        ip = self.ip_entry.get()  
        port = int(self.port_entry.get())  
        username = self.username_entry.get()

        if username:
            self.result = (ip, port, username)
            self.window.destroy()
        else:
            messagebox.showerror("Error", "Username tidak boleh kosong!")

    def run(self):
        self.window.mainloop()
        return self.result

class ChatClient:
    def __init__(self, username, host, port):
        self.root = tk.Tk()
        self.root.title(f"Chat App - {username}")
        self.username = username

        # Set font Poppins
        self.font = tkfont.Font(family="Poppins", size=12)

        # Generate RSA key pair
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.public_key_pem()

        print("\nPrivate Key:")
        print(self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode())
        
        print("\nPublic Key:")
        print(self.public_key)

        # Dictionary untuk menyimpan public key user lain
        self.user_public_keys = {}  # {username: public_key_pem}

        # Dictionary untuk menyimpan history chat
        self.chat_history = {}  # {username: [(sender, message)]}

        # Setup socket
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.client_socket.connect((host, port))
        except Exception as e:
            messagebox.showerror("Error", f"Tidak dapat terhubung ke server: {e}")
            raise e

        # Kirim username dan public key
        client_info = {
            'username': username,
            'public_key': self.public_key
        }
        self.client_socket.send(json.dumps(client_info).encode())

        self.setup_gui()

        self.running = True
        threading.Thread(target=self.receive_messages, daemon=True).start()

    def public_key_pem(self):
        return self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

    def setup_gui(self):
        self.style = ttk.Style()
        self.root.configure(bg="#1a1f3d")
        self.style.configure("CustomFrame.TFrame", background="#3c488c")

        # Frame untuk daftar user online
        self.users_frame = ttk.Frame(self.root, style="CustomFrame.TFrame")  
        self.users_frame.pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=5)

        # Header user online
        tk.Label(self.users_frame, text="Users Online:", bg="#3c488c", fg="white", font=self.font).pack() 
        self.users_listbox = tk.Listbox(self.users_frame, width=20, bg="#bec4eb", fg="#1a1f3d", font=self.font) 
        self.users_listbox.pack(fill=tk.Y, expand=True)
        self.users_listbox.bind('<<ListboxSelect>>', self.on_select_user)

        # Frame untuk chat
        self.chat_frame = ttk.Frame(self.root, style="CustomFrame.TFrame") 
        self.chat_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Header pilih user
        self.selected_user = None
        self.chat_label = tk.Label(self.chat_frame, text="Pilih user untuk mulai chat", bg="#3c488c", fg="white", font=self.font) 
        self.chat_label.pack()

        self.chat_area = scrolledtext.ScrolledText(self.chat_frame, wrap=tk.WORD, state='disabled', height=15, width=50, bg="#bec4eb", fg="white", font=self.font)
        self.chat_area.tag_configure('sender', foreground='#2a313d', justify='right')
        self.chat_area.tag_configure('receiver', foreground='#2b5aa6', justify='left')  
        self.chat_area.pack(fill=tk.BOTH, expand=True)

        self.message_frame = ttk.Frame(self.chat_frame)
        self.message_frame.pack(fill=tk.X, pady=5)

        # Entry chat user
        self.message_entry = tk.Entry(self.message_frame, bg="#bec4eb", fg="#1a1f3d", font=self.font)
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.message_entry.bind("<Return>", self.send_message)

        # Tombol kirim pesan
        self.send_button = tk.Button(self.message_frame, text="Kirim", command=self.send_message, bg="#7a6b1d", fg="white", font=self.font)
        self.send_button.pack(side=tk.RIGHT, padx=5)

    def on_select_user(self, event):
        selection = self.users_listbox.curselection()
        if selection:
            self.selected_user = self.users_listbox.get(selection[0])
            self.chat_label.config(text=f"{self.selected_user}")
            self.update_chat_display()

    def update_chat_display(self):
        self.chat_area.configure(state='normal')
        self.chat_area.delete(1.0, tk.END)

        if self.selected_user in self.chat_history:
            for sender, message in self.chat_history[self.selected_user]:
                if sender == self.username:  
                    self.chat_area.insert(tk.END, f"{self.username} (Anda): ", 'sender')
                    self.chat_area.insert(tk.END, f"{message}\n", 'sender')
                else:  
                    self.chat_area.insert(tk.END, f"{sender}: ", 'receiver')
                    self.chat_area.insert(tk.END, f"{message}\n", 'receiver')

        self.chat_area.configure(state='disabled')
        self.chat_area.see(tk.END)

    def store_message(self, sender, receiver, message):
        # Simpan pesan dalam history chat
        if receiver not in self.chat_history:
            self.chat_history[receiver] = []
        self.chat_history[receiver].append((sender, message))

        # Update tampilan jika chat dengan user yang dipilih
        if self.selected_user == receiver:
            self.update_chat_display()

    def send_message(self, event=None):
        if not self.selected_user:
            messagebox.showwarning("Peringatan", "Pilih user terlebih dahulu!")
            return

        message = self.message_entry.get()
        if message:
            try:
                if self.selected_user not in self.user_public_keys:
                    messagebox.showerror("Error", "Public key pengguna tidak ditemukan!")
                    return

                target_public_key_pem = self.user_public_keys[self.selected_user]
                target_public_key = serialization.load_pem_public_key(
                    target_public_key_pem.encode(),
                    backend=default_backend()
                )

                encrypted_message = target_public_key.encrypt(
                    message.encode(),
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )

                message_data = {
                    'to': self.selected_user,
                    'message': encrypted_message.hex()
                }
                self.client_socket.send(json.dumps(message_data).encode())

                # Simpan pesan ke history
                self.store_message(self.username, self.selected_user, message)

                print(f"\nPesan Asli: {message}")
                print(f"Pesan Terenkripsi: {encrypted_message.hex()}")

                self.message_entry.delete(0, tk.END)

            except Exception as e:
                print(f"Error sending message: {e}")
                messagebox.showerror("Error", f"Gagal mengirim pesan: {e}")

    def receive_messages(self):
        while self.running:
            try:
                data = self.client_socket.recv(4096)
                if not data:
                    break

                message_data = json.loads(data.decode())

                if 'type' in message_data and message_data['type'] == 'online_users':
                    self.user_public_keys = {
                        username: data['public_key']
                        for username, data in message_data['users'].items()
                    }
                    self.update_online_users(list(message_data['users'].keys()))
                else:
                    sender = message_data['from']
                    encrypted_message = bytes.fromhex(message_data['message'])

                    try:
                        decrypted_message = self.private_key.decrypt(
                            encrypted_message,
                            padding.OAEP(
                                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=None
                            )
                        ).decode()

                        print(f"\nPesan Terenkripsi Diterima: {encrypted_message.hex()}")
                        print(f"Pesan Terdekripsi: {decrypted_message}")

                        # Simpan pesan ke history
                        self.store_message(sender, sender, decrypted_message)

                    except Exception as e:
                        print(f"Error decrypting message: {e}")

            except Exception as e:
                print(f"Error receiving message: {e}")
                if self.running:
                    messagebox.showerror("Error", "Koneksi terputus!")
                    self.root.destroy()
                break

    def update_online_users(self, users):
        self.users_listbox.delete(0, tk.END)
        for user in users:
            self.users_listbox.insert(tk.END, user)

    def run(self):
        try:
            self.root.mainloop()
        finally:
            self.running = False
            self.client_socket.close()

if __name__ == "__main__":
    login_window = LoginWindow()
    result = login_window.run()

    if result:
        host, port, username = result
        try:
            client = ChatClient(username, host, port)
            client.run()
        except Exception as e:
            messagebox.showerror("Error", f"Gagal menjalankan aplikasi: {e}")
