import os
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode, urlsafe_b64decode
import importlib.util

def generate_key(password, salt):
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
        backend=default_backend()
    )
    key = kdf.derive(password)
    return key

def encrypt(data, password):
    salt = os.urandom(16)
    key = generate_key(password, salt)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()
    return urlsafe_b64encode(salt + iv + encrypted_data)

def decrypt(encrypted_data, password, decryption_script_path):
    spec = importlib.util.spec_from_file_location("decryption_script", decryption_script_path)
    decryption_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(decryption_module)

    return decryption_module.decrypt(encrypted_data, password)

def encrypt_data():
    password = password_entry.get().encode()
    data = data_entry.get().encode()
    encrypted_data = encrypt(data, password)
    result_text.set(f"Encrypted data: {encrypted_data.decode()}")

def decrypt_data():
    password = password_entry.get().encode()
    encrypted_data = encrypted_entry.get().encode()
    usb_path = filedialog.askdirectory(title="Select USB Drive")
    decryption_script_path = os.path.join(usb_path, 'decryption_script.py')
    
    if not os.path.exists(decryption_script_path):
        messagebox.showerror("Error", "Decryption script not found on USB drive")
        return
    
    try:
        decrypted_data = decrypt(encrypted_data, password, decryption_script_path)
        result_text.set(f"Decrypted data: {decrypted_data.decode()}")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to decrypt data: {e}")

# Create the main window
root = tk.Tk()
root.title("Encryption/Decryption GUI")

# Create and place the widgets
tk.Label(root, text="Password:").grid(row=0, column=0, padx=10, pady=5)
password_entry = tk.Entry(root, show='*', width=50)
password_entry.grid(row=0, column=1, padx=10, pady=5)

tk.Label(root, text="Data to Encrypt:").grid(row=1, column=0, padx=10, pady=5)
data_entry = tk.Entry(root, width=50)
data_entry.grid(row=1, column=1, padx=10, pady=5)

encrypt_button = tk.Button(root, text="Encrypt", command=encrypt_data)
encrypt_button.grid(row=2, column=1, padx=10, pady=5)

tk.Label(root, text="Encrypted Data:").grid(row=3, column=0, padx=10, pady=5)
encrypted_entry = tk.Entry(root, width=50)
encrypted_entry.grid(row=3, column=1, padx=10, pady=5)

decrypt_button = tk.Button(root, text="Decrypt", command=decrypt_data)
decrypt_button.grid(row=4, column=1, padx=10, pady=5)

result_text = tk.StringVar()
result_label = tk.Label(root, textvariable=result_text, wraplength=400, justify="left")
result_label.grid(row=5, column=0, columnspan=2, padx=10, pady=10)

# Start the GUI event loop
root.mainloop()
