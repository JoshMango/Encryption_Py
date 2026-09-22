"""
crypto_utils.py
----------------
Core encryption / decryption logic for the Encryption & Decryption demo app.

Algorithm summary (see documentation PDF for full explanation):
    1. The user supplies a plaintext message and a password.
    2. A random 16-byte SALT is generated (encryption only).
    3. PBKDF2-HMAC-SHA256 stretches the password + salt into a 256-bit AES key
       (100,000 iterations, to slow down brute-force / dictionary attacks).
    4. A random 16-byte IV (Initialization Vector) is generated.
    5. The plaintext is PKCS7-padded and encrypted with AES-256 in CBC mode.
    6. SALT + IV + CIPHERTEXT are concatenated and Base64-encoded so the result
       is a single, safely copy/paste-able text string.

Decryption reverses the process: Base64-decode -> split out salt/IV/ciphertext
-> re-derive the same key from the supplied password + salt -> AES-CBC decrypt
-> remove PKCS7 padding.

Because the salt is stored alongside the ciphertext, the *same* password will
always be able to decrypt the message, while two encryptions of the same
plaintext with the same password will still produce different output
(because the salt and IV are re-randomized every time). This is standard,
real-world practice for password-based encryption.
"""

import base64
import os

from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ---- Tunable constants -----------------------------------------------------
SALT_SIZE = 16          # bytes
IV_SIZE = 16             # bytes (AES block size)
KEY_SIZE = 32            # bytes -> AES-256
PBKDF2_ITERATIONS = 100_000


class CryptoError(Exception):
    """Raised for any expected, user-facing encryption/decryption failure."""
    pass


def _derive_key(password: str, salt: bytes) -> bytes:
    """Turn a human password + salt into a 256-bit AES key using PBKDF2-HMAC-SHA256."""
    if not password:
        raise CryptoError("Password cannot be empty.")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_text(plaintext: str, password: str) -> str:
    """
    Encrypt plaintext with a password.
    Returns a Base64 string containing: salt | iv | ciphertext
    """
    if plaintext == "":
        raise CryptoError("There is no message to encrypt. Please type something first.")
    if not password:
        raise CryptoError("Please enter a password/key to encrypt with.")

    salt = os.urandom(SALT_SIZE)
    iv = os.urandom(IV_SIZE)
    key = _derive_key(password, salt)

    # PKCS7 pad the plaintext to a multiple of the AES block size (128 bits)
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext.encode("utf-8")) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    payload = salt + iv + ciphertext
    return base64.b64encode(payload).decode("utf-8")


def decrypt_text(encoded_payload: str, password: str) -> str:
    """
    Decrypt a Base64 string previously produced by encrypt_text().
    Raises CryptoError with a friendly message on any failure
    (bad password, corrupted/tampered data, wrong format, etc.).
    """
    if not encoded_payload:
        raise CryptoError("There is no encrypted message to decrypt. Please paste ciphertext first.")
    if not password:
        raise CryptoError("Please enter the password/key used to encrypt this message.")

    try:
        payload = base64.b64decode(encoded_payload, validate=True)
    except Exception:
        raise CryptoError(
            "The encrypted text is not valid Base64 data. "
            "Make sure you copied the full, unmodified ciphertext."
        )

    if len(payload) < SALT_SIZE + IV_SIZE + algorithms.AES.block_size // 8:
        raise CryptoError("The encrypted text is too short / incomplete to be valid.")

    salt = payload[:SALT_SIZE]
    iv = payload[SALT_SIZE:SALT_SIZE + IV_SIZE]
    ciphertext = payload[SALT_SIZE + IV_SIZE:]

    if len(ciphertext) % (algorithms.AES.block_size // 8) != 0:
        raise CryptoError("The ciphertext is corrupted (invalid block size).")

    key = _derive_key(password, salt)

    try:
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
    except (ValueError,) as exc:
        # Wrong password (almost always) or corrupted ciphertext -> padding/format breaks
        raise CryptoError(
            "Decryption failed. This usually means the password is wrong, "
            "or the encrypted text was altered/corrupted."
        ) from exc

    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise CryptoError(
            "Decryption produced unreadable data. The password is likely incorrect."
        )
