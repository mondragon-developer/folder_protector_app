import os
from fileEncryptor import FileEncryptor

class FolderEncryptor:
    @staticmethod
    def encrypt_folder(folder_path, password):
        """
        Encrypts all files in a specified folder using the given password.
        Iterates over all files in the folder and calls the FileEncryptor.encrypt_file method.
        """
        for root, _, files in os.walk(folder_path):
            for file in files:
                FileEncryptor.encrypt_file(os.path.join(root, file), password)

        FileEncryptor.save_password(password, folder_path)

    @staticmethod
    def decrypt_folder(folder_path, password):
        """
        Decrypts all encrypted files (.enc) in a specified folder using the given password.
        Validates the provided password against the saved password.
        Iterates over all files in the folder and calls the FileEncryptor.decrypt_file method for .enc files.
        """
        FileEncryptor.validate_password(password, folder_path)

        for root, _, files in os.walk(folder_path):
            for file in files:
                if file.endswith('.enc'):  # Only process encrypted files
                    try:
                        FileEncryptor.decrypt_file(os.path.join(root, file), password)
                    except ValueError as e:
                        raise ValueError(f"Failed to decrypt {file}: {str(e)}")    
