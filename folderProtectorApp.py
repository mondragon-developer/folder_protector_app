import tkinter as tk
from tkinter import filedialog, messagebox
from folderEncryptor import FolderEncryptor

class FolderProtectorApp:
    def __init__(self, root):
        """
        Initializes the GUI application.
        Sets up the main window, labels, entry fields, and buttons.
        """
        self.root = root
        self.root.title("Folder Protector")

        self.password_label = tk.Label(root, text="Password:")
        self.password_label.pack(pady=10)

        self.password_entry = tk.Entry(root, show="*")
        self.password_entry.pack(pady=5)

        self.encrypt_button = tk.Button(root, text="Encrypt Folder", command=self.select_folder_to_encrypt)
        self.encrypt_button.pack(pady=10)

        self.decrypt_button = tk.Button(root, text="Open Folder", command=self.select_folder_to_decrypt)
        self.decrypt_button.pack(pady=10)

    def select_folder_to_encrypt(self):
        """
        Opens a file dialog to select a folder to encrypt.
        Encrypts all files in the selected folder using the provided password.
        """
        folder_path = filedialog.askdirectory()
        if folder_path:
            password = self.password_entry.get()
            if password:
                FolderEncryptor.encrypt_folder(folder_path, password)
                messagebox.showinfo("Success", "Folder encrypted successfully.")
            else:
                messagebox.showerror("Error", "Please enter a password.")

    def select_folder_to_decrypt(self):
        """
        Opens a file dialog to select a folder to decrypt.
        Decrypts all encrypted files in the selected folder using the provided password.
        """
        folder_path = filedialog.askdirectory()
        if folder_path:
            password = self.password_entry.get()
            if password:
                try:
                    FolderEncryptor.decrypt_folder(folder_path, password)
                    messagebox.showinfo("Success", "Folder decrypted successfully.")
                except Exception as e:
                    messagebox.showerror("Error", "Failed to decrypt folder. Check your password.")
            else:
                messagebox.showerror("Error", "Please enter a password.")

def main():
    """
    Main function to run the GUI application.
    Initializes the main window and starts the event loop.
    """
    root = tk.Tk()
    app = FolderProtectorApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
