import base64
import os

from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ---- the changable constants -----------------------------------------------------
SALT_SIZE = 16          # bytes
IV_SIZE = 16             # bytes (AES block size)
KEY_SIZE = 32            # bytes -> AES-256  or  256 bits
PBKDF2_ITERATIONS = 100_000     # how many cryptographic hashing function runs to secure password


# ---- for Error Message-----------------------------------------------------
class CryptoError(Exception):
    """Raised for any expected, user-facing encryption/decryption failure."""
    pass 


# ---- for converting human password text into 256-bit AES key  -----------------------------------------------------
def _derive_key(password: str, salt: bytes) -> bytes:
    """Turn a human password + salt into a 256-bit AES key using PBKDF2-HMAC-SHA256."""

    # check if password is empty then print that error message
    if not password:
        raise CryptoError("Password cannot be empty.")

        
    # this is the method which is like a blueprint, it initializes the settings without running the math yet.
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), # use SHA256 as the hash function algorithm for PBKDF2
        length=KEY_SIZE, # derive a 256-bit key (32 bytes) 
        salt=salt, # use the provided salt from parameters
        iterations=PBKDF2_ITERATIONS, # use 100,000 iterations for key stretching
    )

    return kdf.derive(password.encode("utf-8")) 
    # this runs the password hashing process and derives the key from the password and salt, returning it as bytes




# ---- for encrypting user input text -----------------------------------------------------
def encrypt_text(plaintext: str, password: str) -> str:
    """
    Encrypt plaintext with a password.
    Returns a Base64 string containing: salt | iv | ciphertext
    """

    # check if plaintext is empty then print that error message
    if plaintext == "":
        raise CryptoError("There is no message to encrypt. Please type something first.")

    
    # check if password is empty then print that error message
    if not password:
        raise CryptoError("Please enter a password/key to encrypt with.")


    # for generating a random salt and IV
    salt = os.urandom(SALT_SIZE)
    iv = os.urandom(IV_SIZE)

    # pass the password and salt to the derive_key function to generate the AES key
    key = _derive_key(password, salt)


    # PKCS7 pad the plaintext to a multiple of the AES block size (128 bits)
    padder = padding.PKCS7(algorithms.AES.block_size).padder() # create a PKCS7 padder object with AES block size
    padded_data = padder.update(plaintext.encode("utf-8")) + padder.finalize() # pad the plaintext and finalize the padding


    # next we encrypt the padded plaintext with AES-256-CBC / Cipher so...


    # create a Cipher object with AES-256 in CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))  # this is the blueprint that doesnt process data yet.
    encryptor = cipher.encryptor()  # create an encryptor object
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()  # encrypt the padded data and finalize the encryption

    # combine the salt, iv, and ciphertext into a single payload, which will be Base64-encoded for easy storage/transmission
    payload = salt + iv + ciphertext

    # finally, return the Base64-encoded string of the payload
    return base64.b64encode(payload).decode("utf-8")




# ---- for decrypting user input encrypted text -----------------------------------------------------
def decrypt_text(encoded_payload: str, password: str) -> str:
    """
    Decrypt a Base64 string previously produced by encrypt_text().
    Raises CryptoError with a friendly message on any failure
    (bad password, corrupted/tampered data, wrong format, etc.).
    """

    # if encrypted message is empty then print that error message
    if not encoded_payload: 
        raise CryptoError("There is no encrypted message to decrypt. Please paste ciphertext first.")
    
    # if password is empty then print that error message
    if not password:
        raise CryptoError("Please enter the password/key used to encrypt this message.")
        

    # decode the Base64-encoded payload into bytes using base64.b64decode()
    try:
        payload = base64.b64decode(encoded_payload, validate=True)
        # the `validate=True` argument makes sure that the input is a valid Base64

    # if input is not a valid Base64 string, then raise a `binascii.Error` 
    # which we catch and raise a `CryptoError` with a user-friendly message.
    except Exception:  
        raise CryptoError(
            "The encrypted text is not valid Base64 data. "
            "Make sure you copied the full, unmodified ciphertext."
        )

    
    # check that the payload is long enough to contain salt + iv + at least one block of ciphertext
    # AES block size is 16 bytes, so the minimum length is SALT_SIZE + IV_SIZE + 16
    if len(payload) < SALT_SIZE + IV_SIZE + algorithms.AES.block_size // 8:
        raise CryptoError("The encrypted text is too short / incomplete to be valid.")

    # split the payload into salt, iv, and ciphertext
    salt = payload[:SALT_SIZE]
    iv = payload[SALT_SIZE:SALT_SIZE + IV_SIZE]
    ciphertext = payload[SALT_SIZE + IV_SIZE:]

    # if length of ciphertext is not a multiple of AES block size, then it is corrupted
    if len(ciphertext) % (algorithms.AES.block_size // 8) != 0:
        raise CryptoError("The ciphertext is corrupted (invalid block size).")

    # pass the password and salt to the derive_key function to generate the AES key
    key = _derive_key(password, salt)


    # decrypt the ciphertext with AES-256-CBC
    try:
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv)) # create a Cipher object with AES-256 in CBC mode, this is the blueprint that doesnt process data yet.
        decryptor = cipher.decryptor()  # create a decryptor object
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()  # decrypt the ciphertext and finalize the decryption

        # next we PKCS7 unpad the decrypted data to remove the padding added during encryption so...

        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder() # create a PKCS7 unpadder object with AES block size, this is the blueprint that doesnt process data yet.
        data = unpadder.update(padded_data) + unpadder.finalize()  # unpad the decrypted data and finalize the unpadding

    # if any error happens in decryption or unpadding, it is likely because of a wrong password or corrupted ciphertext. 
    # We catch the ValueError and raise a CryptoError with a user-friendly message.
    except (ValueError,) as exc: 
        # wrong password (almost always) or corrupted ciphertext -> padding/format breaks
        raise CryptoError(
            "Decryption failed. This usually means the password is wrong, "
            "or the encrypted text was altered/corrupted."
        ) from exc

    # if the decrypted data is valid UTF-8, then return it.
    try:
        return data.decode("utf-8")

    # if the decrypted data is not valid UTF-8, then raise a CryptoError with a user-friendly message.
    except UnicodeDecodeError:
        raise CryptoError(
            "Decryption produced unreadable data. The password is likely incorrect."
        )
