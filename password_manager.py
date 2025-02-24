import hashlib
import os
import json
import base64
import secrets
import tkinter as tk
from tkinter import messagebox, simpledialog
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class PasswordManager:
    def __init__(self, master_password):
        self.master_key = self._derive_key(master_password)
        self.passwords = {}
        self.file_path = "passwords.json"
        self.load_passwords()

    def _derive_key(self, password):
        return hashlib.sha256(password.encode()).digest()

    def _encrypt(self, plaintext):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.master_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        padded_plaintext = plaintext + (16 - len(plaintext) % 16) * " "
        ciphertext = encryptor.update(padded_plaintext.encode()) + encryptor.finalize()
        return base64.b64encode(iv + ciphertext).decode()

    def _decrypt(self, encrypted_text):
        data = base64.b64decode(encrypted_text)
        iv, ciphertext = data[:16], data[16:]
        cipher = Cipher(algorithms.AES(self.master_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ciphertext) + decryptor.finalize()
        return decrypted.decode().strip()

    def add_password(self, site, username, password):
        encrypted_password = self._encrypt(password)
        self.passwords[site] = {"username": username, "password": encrypted_password}
        self.save_passwords()

    def get_password(self, site):
        if site in self.passwords:
            return {
                "username": self.passwords[site]["username"],
                "password": self._decrypt(self.passwords[site]["password"]),
            }
        return None

    def save_passwords(self):
        with open(self.file_path, "w") as file:
            json.dump(self.passwords, file)

    def load_passwords(self):
        if os.path.exists(self.file_path):
            with open(self.file_path, "r") as file:
                self.passwords = json.load(file)

class VaultLockGUI:
    def __init__(self, root, password_manager):
        self.root = root
        self.pm = password_manager
        self.root.title("VaultLock - Password Manager")
        self.root.geometry("400x300")
        
        self.label = tk.Label(root, text="VaultLock", font=("Arial", 16))
        self.label.pack(pady=10)
        
        self.site_entry = tk.Entry(root, width=30)
        self.site_entry.pack()
        self.site_entry.insert(0, "Enter site")
        
        self.user_entry = tk.Entry(root, width=30)
        self.user_entry.pack()
        self.user_entry.insert(0, "Enter username")
        
        self.pass_entry = tk.Entry(root, width=30, show="*")
        self.pass_entry.pack()
        self.pass_entry.insert(0, "Enter password")
        
        self.add_button = tk.Button(root, text="Add Password", command=self.add_password)
        self.add_button.pack(pady=5)
        
        self.get_button = tk.Button(root, text="Get Password", command=self.get_password)
        self.get_button.pack(pady=5)
        
    def add_password(self):
        site = self.site_entry.get()
        username = self.user_entry.get()
        password = self.pass_entry.get()
        self.pm.add_password(site, username, password)
        messagebox.showinfo("Success", "Password saved!")

    def get_password(self):
        site = simpledialog.askstring("Retrieve Password", "Enter site:")
        data = self.pm.get_password(site)
        if data:
            messagebox.showinfo("Password", f"Username: {data['username']}\nPassword: {data['password']}")
        else:
            messagebox.showerror("Error", "No data found!")

if __name__ == "__main__":
    master_pass = simpledialog.askstring("Master Password", "Set Master Password:", show="*")
    pm = PasswordManager(master_pass)
    root = tk.Tk()
    app = VaultLockGUI(root, pm)
    root.mainloop()

