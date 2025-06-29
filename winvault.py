
import os
import shutil
import tkinter as tk
from tkinter import filedialog, messagebox
import zipfile
import tempfile
import secrets
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import re

APP_EXT = ".wvsb"
BACKEND = default_backend()
ITERATIONS = 100_000

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
        backend=BACKEND
    )
    return kdf.derive(password.encode())

def encrypt_data(data: bytes, password: str) -> bytes:
    salt = secrets.token_bytes(16)
    key = derive_key(password, salt)
    iv = secrets.token_bytes(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=BACKEND)
    encryptor = cipher.encryptor()
    pad_len = 16 - len(data) % 16
    padded_data = data + bytes([pad_len]) * pad_len
    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    return salt + iv + encrypted

def decrypt_data(encrypted_data: bytes, password: str) -> bytes:
    salt = encrypted_data[:16]
    iv = encrypted_data[16:32]
    data = encrypted_data[32:]
    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=BACKEND)
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(data) + decryptor.finalize()
    pad_len = padded_data[-1]
    return padded_data[:-pad_len]

def encrypt_folder(folder_path, password):
    temp_zip = tempfile.NamedTemporaryFile(delete=False, suffix=".zip")
    temp_zip_path = temp_zip.name
    temp_zip.close()
    with zipfile.ZipFile(temp_zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, _, files in os.walk(folder_path):
            for file in files:
                full_path = os.path.join(root, file)
                arcname = os.path.relpath(full_path, start=folder_path)
                zipf.write(full_path, arcname)

    with open(temp_zip_path, "rb") as f:
        data = f.read()

    encrypted_data = encrypt_data(data, password)
    out_file = folder_path + APP_EXT
    with open(out_file, "wb") as f:
        f.write(encrypted_data)

    os.remove(temp_zip_path)
    shutil.rmtree(folder_path)  # Securely delete original folder
    messagebox.showinfo("Success", f"Folder locked to: {out_file}")

def decrypt_file(file_path, password):
    with open(file_path, "rb") as f:
        encrypted_data = f.read()

    try:
        data = decrypt_data(encrypted_data, password)
    except Exception:
        messagebox.showerror("Error", "Incorrect password or file is corrupted (decryption failed).")
        return

    if not data.startswith(b'PK'):
        messagebox.showerror("Error", "Incorrect password or the file has been tampered with.")
        return

    extract_dir = file_path.replace(APP_EXT, "")
    temp_zip = tempfile.NamedTemporaryFile(delete=False, suffix=".zip")
    temp_zip_path = temp_zip.name
    temp_zip.close()

    with open(temp_zip_path, "wb") as f:
        f.write(data)

    with zipfile.ZipFile(temp_zip_path, 'r') as zipf:
        zipf.extractall(extract_dir)

    os.remove(temp_zip_path)
    messagebox.showinfo("Success", f"Unlocked to: {extract_dir}")

def password_strength(password):
    length = len(password)
    strength = 0
    if re.search(r"[a-z]", password): strength += 1
    if re.search(r"[A-Z]", password): strength += 1
    if re.search(r"\d", password): strength += 1
    if re.search(r"[^a-zA-Z0-9]", password): strength += 1
    if length >= 12: strength += 1
    return strength

def update_strength_label(event):
    pwd = pwd_entry.get()
    score = password_strength(pwd)
    messages = ["Very Weak", "Weak", "Okay", "Strong", "Very Strong", "Excellent"]
    strength_label.config(text=f"Strength: {messages[min(score, 5)]}")

def lock():
    folder = filedialog.askdirectory()
    if not folder:
        return
    password = pwd_entry.get()
    if not password:
        messagebox.showerror("Error", "Please enter a password.")
        return
    encrypt_folder(folder, password)

def unlock():
    file = filedialog.askopenfilename(filetypes=[("WinVault Files", f"*{APP_EXT}")])
    if not file:
        return
    password = pwd_entry.get()
    if not password:
        messagebox.showerror("Error", "Please enter a password.")
        return
    decrypt_file(file, password)

root = tk.Tk()
root.title("WinVault")
root.geometry("360x240")
root.resizable(False, False)
root.configure(bg="#1e1e1e")

title = tk.Label(root, text="WinVault", font=("Segoe UI", 20), fg="#ffffff", bg="#1e1e1e")
title.pack(pady=(20, 10))

pwd_entry = tk.Entry(root, show="*", width=30, font=("Segoe UI", 10))
pwd_entry.pack()
pwd_entry.bind("<KeyRelease>", update_strength_label)

strength_label = tk.Label(root, text="Strength: ", fg="#bbbbbb", bg="#1e1e1e", font=("Segoe UI", 9))
strength_label.pack(pady=(5, 10))

tk.Button(root, text="🔒 Lock Folder", command=lock, bg="#2d89ef", fg="white", width=20, relief=tk.FLAT).pack(pady=5)
tk.Button(root, text="🔓 Unlock File", command=unlock, bg="#2d89ef", fg="white", width=20, relief=tk.FLAT).pack(pady=5)

footer = tk.Label(root, text=".wvsb encrypted | AES-256 | Files auto-deleted after lock", fg="#666666", bg="#1e1e1e", font=("Segoe UI", 8))
footer.pack(side="bottom", pady=10)

root.mainloop()
