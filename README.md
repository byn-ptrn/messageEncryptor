# Message Encryptor/Decryptor

A secure message encryption and decryption tool using AES-256-CBC encryption algorithm.

## Features

- Encrypt messages using AES-256 bit encryption
- Decrypt encrypted messages with the correct password
- Hidden password input for enhanced security
- Command-line interface with menu system
- Strong encryption using salt and IV for added security

## Technical Details

- Encryption Algorithm: AES-256-CBC
- Key Derivation: PBKDF2 with SHA256
- Salt: 16 bytes random
- IV (Initialization Vector): 16 bytes random
- Password Protection: Hidden input using getpass
- Encoding: Base64 for encrypted messages

## Security Features

- Unique salt for each encryption
- Random IV generation
- Secure key derivation using PBKDF2
- Password masking during input
- Proper padding implementation
- Error handling for invalid messages/passwords

## Requirements

- Python 3.7 or higher
- Install required library:
  ```
  pip install cryptography
  ```
- Built-in libraries used:
  - getpass
  - base64
  - os

## Usage

1. Run the script
2. Choose an option:
   - 1: Encrypt a message
   - 2: Decrypt a message
   - 3: Exit
3. Follow the prompts to encrypt/decrypt messages

## Note

- Keep your password safe - lost passwords cannot be recovered
- Store encrypted messages carefully
- Designed for secure message encryption on desktop systems
