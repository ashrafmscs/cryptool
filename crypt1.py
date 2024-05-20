from cryptography.fernet import Fernet, InvalidToken
import hashlib
import os
import getpass
from base64 import urlsafe_b64encode

def derive_key_from_password(password):
    """Derive a Fernet key from a given password using SHA-256."""
    digest = hashlib.sha256(password.encode()).digest()
    return urlsafe_b64encode(digest)

def encrypt(filename, key):
    f = Fernet(key)
    with open(filename, "rb") as file:
        file_data = file.read()
        encrypted_data = f.encrypt(file_data)
    with open(filename, "wb") as file:
        file.write(encrypted_data)

def decrypt(filename, key):
    f = Fernet(key)
    with open(filename, "rb") as file:
        encrypted_data = file.read()
        try:
            decrypted_data = f.decrypt(encrypted_data)
        except InvalidToken:
            print("Invalid key")
            return False
    with open(filename, "wb") as file:
        file.write(decrypted_data)
    return True

def hash_file(filename):
    """Generate a SHA-256 hash of the file."""
    sha256 = hashlib.sha256()
    with open(filename, "rb") as file:
        while chunk := file.read(8192):
            sha256.update(chunk)
    return sha256.hexdigest()

def encrypt_files(filenames, password):
    key = derive_key_from_password(password)
    for filename in filenames:
        if os.path.exists(filename):
            encrypt(filename, key)
            print(f"File '{filename}' encrypted successfully!")
        else:
            print(f"File '{filename}' not found. Please check the file name and try again.")

def decrypt_files(filenames, password):
    key = derive_key_from_password(password)
    for filename in filenames:
        if os.path.exists(filename):
            success = decrypt(filename, key)
            if success:
                print(f"File '{filename}' decrypted successfully!")
        else:
            print(f"File '{filename}' not found. Please check the file name and try again.")

def main():
    choice = input("Enter 'E' to encrypt or 'D' to decrypt files: ").lower()
    filenames = input("Enter the file names to process (separated by commas): ").split(',')
    filenames = [filename.strip() for filename in filenames]

    if choice == 'e':
        password = getpass.getpass("Enter a password to encrypt the files: ")
        encrypt_files(filenames, password)
    elif choice == 'd':
        password = getpass.getpass("Enter the password to decrypt the files: ")
        decrypt_files(filenames, password)
    else:
        print("Invalid choice. Please enter 'E' to encrypt files or 'D' to decrypt files.")

if __name__ == "__main__":
    main()
