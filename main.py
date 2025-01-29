from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import base64

def derive_key(password: str, salt: bytes) -> bytes:
    """Generate encryption key from password and salt using PBKDF2"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(password.encode())

def encrypt_message(message: str, password: str) -> str:
    """Encrypt a message using AES-256-CBC with a password"""
    # Generate random salt and IV
    salt = os.urandom(16)
    iv = os.urandom(16)
    
    # Derive encryption key from password
    key = derive_key(password, salt)
    
    # Create cipher and encryptor
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    
    # Pad message to be multiple of 16 bytes
    padded_message = message.encode()
    padding_length = 16 - (len(padded_message) % 16)
    padded_message += bytes([padding_length]) * padding_length
    
    # Encrypt message
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()
    
    # Combine salt + IV + ciphertext and encode as base64
    encrypted_data = salt + iv + ciphertext
    return base64.b64encode(encrypted_data).decode('utf-8')

def main():
    print("Message Encryptor - AES-256")
    print("-" * 30)
    
    # Get user input
    message = input("Enter message to encrypt: ")
    password = input("Enter encryption password: ")
    
    try:
        # Encrypt and display result
        encrypted = encrypt_message(message, password)
        print("\nEncrypted message:")
        print(encrypted)
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()