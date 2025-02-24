import hashlib
import os
import json
import base64
import secrets
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

if __name__ == "__main__":
    master_pass = input("Set Master Password: ")
    pm = PasswordManager(master_pass)

    while True:
        choice = input("(1) Add Password\n(2) Get Password\n(3) Exit\nChoose: ")
        if choice == "1":
            site = input("Enter site: ")
            username = input("Enter username: ")
            password = input("Enter password: ")
            pm.add_password(site, username, password)
            print("Password saved!")
        elif choice == "2":
            site = input("Enter site: ")
            data = pm.get_password(site)
            if data:
                print(f"Username: {data['username']}, Password: {data['password']}")
            else:
                print("No data found!")
        elif choice == "3":
            break
        else:
            print("Invalid choice!")
