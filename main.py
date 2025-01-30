from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import base64
from getpass import getpass

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

def decrypt_message(encrypted_message: str, password: str) -> str:
    """Decrypt a message using AES-256-CBC with a password"""
    try:
        # Decode base64 and extract salt, IV, and ciphertext
        encrypted_data = base64.b64decode(encrypted_message.encode('utf-8'))
        salt = encrypted_data[:16]
        iv = encrypted_data[16:32]
        ciphertext = encrypted_data[32:]

        # Derive key from password and salt
        key = derive_key(password, salt)

        # Create cipher and decryptor
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()

        # Decrypt and unpad
        padded_message = decryptor.update(ciphertext) + decryptor.finalize()
        padding_length = padded_message[-1]
        message = padded_message[:-padding_length]

        return message.decode('utf-8')
    except Exception as e:
        raise ValueError(f"Decryption failed. Invalid message or wrong password. Error: {e}")

def encrypt_flow():
    """Handle the encryption process"""
    print("\nENCRYPT MESSAGE")
    print("-" * 20)
    message = input("Enter message to encrypt: ")
    password = getpass("Enter encryption password: ")
    
    try:
        encrypted = encrypt_message(message, password)
        print("\nEncrypted message:")
        print(encrypted)
    except Exception as e:
        print(f"Error: {e}")

def decrypt_flow():
    """Handle the decryption process"""
    print("\nDECRYPT MESSAGE")
    print("-" * 20)
    encrypted_message = input("Enter encrypted message: ")
    password = getpass("Enter decryption password: ")
    
    try:
        decrypted = decrypt_message(encrypted_message, password)
        print("\nDecrypted message:")
        print(decrypted)
    except Exception as e:
        print(f"Error: {e}")

def main():
    while True:
        print("\nWelcome to Message Encryptor/Decryptor")
        print("=" * 35)
        print("1. Encrypt Message")
        print("2. Decrypt Message")
        print("3. Exit")
        
        choice = input("\nEnter your choice (1-3): ")
        
        if choice == "1":
            encrypt_flow()
        elif choice == "2":
            decrypt_flow()
        elif choice == "3":
            print("\nGoodbye!")
            break
        else:
            print("\nInvalid choice. Please try again.")
        
        input("\nPress Enter to continue...")

if __name__ == "__main__":
    main()