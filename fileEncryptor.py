import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64

class FileEncryptor:
    @staticmethod
    def derive_key(password, salt):
        """
        Derives a cryptographic key from a password and salt using PBKDF2HMAC with SHA-256.
        This ensures that the same password will generate different keys when used with different salts.
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password.encode())

    @staticmethod
    def encrypt_file(file_path, password):
        """
        Encrypts a file using AES encryption with a password-derived key.
        The encrypted file is saved with a .enc extension, and the original file is deleted.
        """
        salt = os.urandom(16)  # Generate a random salt for key derivation
        key = FileEncryptor.derive_key(password, salt)  # Derive the encryption key
        iv = os.urandom(16)  # Generate a random initialization vector (IV)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        with open(file_path, 'rb') as f:
            data = f.read()  # Read the original file content

        encrypted_data = encryptor.update(data) + encryptor.finalize()  # Encrypt the data

        # Write the salt, IV, and encrypted data to a new file with .enc extension
        with open(file_path + '.enc', 'wb') as f:
            f.write(salt + iv + encrypted_data)

        os.remove(file_path)  # Remove the original unencrypted file

    @staticmethod
    def decrypt_file(file_path, password):
        """
        Decrypts an encrypted file using AES decryption with a password-derived key.
        The decrypted file is saved without the .enc extension, and the encrypted file is deleted.
        """
        with open(file_path, 'rb') as f:
            data = f.read()  # Read the encrypted file content

        salt = data[:16]  # Extract the salt from the file
        iv = data[16:32]  # Extract the IV from the file
        encrypted_data = data[32:]  # The rest is the encrypted data

        key = FileEncryptor.derive_key(password, salt)  # Derive the decryption key
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()  # Decrypt the data

        decrypted_file_path = file_path.replace('.enc', '')  # Remove .enc extension from the file name
        with open(decrypted_file_path, 'wb') as f:
            f.write(decrypted_data)

        os.remove(file_path)  # Remove the encrypted file
