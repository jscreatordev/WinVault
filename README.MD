# 🔐 WinVault

**WinVault** is a secure, minimalist file locker for Windows that lets you lock entire folders into encrypted `.wvsb` files using military-grade AES-256 encryption. Only you — with your password — can unlock them.
---

## 🧩 Features

- 🔒 **AES-256 Encryption**  
  Your files are encrypted with advanced encryption standards and a password-derived key.

- 🗂️ **One-Click Folder Locking**  
  Drag-and-drop simplicity: just select a folder and lock it.

- ✨ **Beautiful UI**  
  Clean, modern dark-mode interface with a real-time password strength meter.

- 💣 **Tamper Protection**  
  Files are stored as `.wvsb` — unreadable and unusable without the right password.

- ❌ **Auto Delete Source**  
  After successful encryption, the original folder is permanently deleted for security.

- 🧠 **No Backdoors. No Recovery.**  
  We don’t store passwords. If you forget your password, your data is gone. Forever.

---

## 🚀 How to Use

### 🔐 Lock a Folder:
1. Open **WinVault.exe**
2. Enter a **strong password**
3. Click **🔒 Lock Folder**
4. Choose the folder you want to protect
5. The app will:
   - Zip and encrypt the folder
   - Save it as a `.wvsb` file
   - **Delete** the original folder

### 🔓 Unlock a `.wvsb` File:
1. Enter the correct password
2. Click **🔓 Unlock File**
3. Choose your `.wvsb` file
4. Your folder will be restored in the same location

---

## 📂 File Format

Encrypted files use a custom `.wvsb` extension, but contain:
- A 16-byte salt
- A 16-byte IV
- AES-256-CBC encrypted zip data

Trying to rename or open it manually will corrupt it.

---

## 🛑 Warnings

- Forgotten password = lost data. No recovery possible.
- WinVault only works on **Windows** (EXE version).
- File deletion is permanent — double-check what you lock.

---

## 🛠 Requirements

- Windows 10 or later
- Python 3.10+ (if using `.py` version)
- Standalone `.exe` version requires no installation

---

## 🧱 Tech Stack

- Language: Python 3
- UI: Tkinter (custom styled)
- Crypto: `cryptography` (PBKDF2 + AES-256-CBC)
- Bundler: PyInstaller for standalone EXE

---

## 📦 Coming Soon

- Cross-platform support (Mac/Linux)
- Stealth mode (tray icon only)
- Fake vaults for decoy unlocks

---

## 🧊 Example Use Case

- Hide personal files  
- Lock away work projects  
- Protect backups from tampering

---

## ❤️ Author

**WinVault** was built with simplicity and security in mind.  
No tracking, no telemetry, no BS. Just clean local file protection.
