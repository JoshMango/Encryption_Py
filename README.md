# Encryption & Decryption Program (Python Desktop App)

A simple desktop GUI application (built with Python's built-in `tkinter`) that
encrypts and decrypts text messages using **AES-256 in CBC mode**, with a
password-based key derived via **PBKDF2-HMAC-SHA256**.

Built for: *Encryption and Decryption Program Development* project.

## Project Structure
```
encryption_app/
├── main.py            # GUI application (entry point) — run this file
├── crypto_utils.py     # Encryption/decryption logic (AES-256-CBC + PBKDF2)
├── requirements.txt    # Python dependencies
└── README.md           # This file
```

## Requirements
- Python 3.8+
- `tkinter` (included with most standard Python installs on Windows/macOS;
  on Linux you may need `sudo apt install python3-tk`)
- `cryptography` package (see requirements.txt)

## Setup (VS Code / terminal)
1. Open this folder in VS Code (`File > Open Folder...`).
2. (Recommended) Create a virtual environment:
   ```bash
   python -m venv venv
   # Windows:
   venv\Scripts\activate
   # macOS/Linux:
   source venv/bin/activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Run the app:
   ```bash
   python main.py
   ```

## How to Use
1. **Encrypt tab** — type (or click "Load Sample" to auto-fill) a message and
   a password, then click **Encrypt ➜**. The Base64 ciphertext appears below;
   click **Copy Output** to copy it.
2. **Decrypt tab** — paste the encrypted text and the same password, then
   click **Decrypt ➜** to recover the original message. Use **Use Last
   Encrypted Result** to auto-load whatever you just encrypted, for a quick
   round-trip test.
3. Try an intentionally **wrong password** or an edited ciphertext to see the
   app's friendly error handling in action — this is a good demo of the
   error-handling requirement.

## Algorithm Overview
See the accompanying PDF documentation (`Encryption_Decryption_Documentation.pdf`)
for the full explanation, real-world application, code breakdown, and sample
input/output.
