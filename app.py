import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
from key_manager import KeyManager
from signer import Signer, SIGNATURES_DIR


class DigitalSignatureApp:
    def __init__(self, root):
        """
        Initializes the main GUI application.
        Sets up the UI components.
        """
        self.root = root
        self.root.title("Digital Signature Application")
        self.root.geometry("500x450")
        self.root.resizable(False, False)
        self.pub_key = None
        self.priv_key = None
        self.setup_ui()

    def setup_ui(self):
        """Sets up the user interface."""
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TButton", font=("Helvetica", 12), padding=10, background="#2E3B4E", foreground="#FFFFFF")
        style.configure("TLabel", font=("Helvetica", 14), foreground="#FFFFFF")
        style.configure("TFrame", background="#1E1E1E")

        frame = ttk.Frame(self.root, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="Digital Signature Application", anchor="center", background="#1E1E1E").pack(pady=10)
        ttk.Button(frame, text="Generate Key Pair", command=self.generate_key_pair).pack(pady=10)
        ttk.Button(frame, text="Load Key Pair", command=self.load_key_pair).pack(pady=10)
        ttk.Button(frame, text="Sign Document", command=self.sign_file).pack(pady=10)
        ttk.Button(frame, text="Verify Signature", command=self.verify_file).pack(pady=10)

        self.root.configure(background="#1E1E1E")

    def generate_key_pair(self):
        """
        Generates a new RSA key pair and saves it.
        Shows a success message when the keys are generated.
        """
        self.pub_key, self.priv_key = KeyManager.generate_keys()
        messagebox.showinfo("Success", "RSA key pair generated and saved successfully.")

    def load_key_pair(self):
        """
        Loads an existing RSA key pair from files.
        Shows a success message if the keys are loaded successfully.
        """
        try:
            self.priv_key = KeyManager.load_private_key()
            self.pub_key = KeyManager.load_public_key()
            messagebox.showinfo("Success", "RSA key pair loaded successfully.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load keys: {e}")

    def sign_file(self):
        """
        Opens a file dialog to select a document for signing.
        Signs the selected document using the loaded private key.
        """
        if not self.priv_key:
            messagebox.showerror("Error", "Private key not loaded or generated.")
            return
        file_path = filedialog.askopenfilename(title="Select a file to sign")
        if file_path:
            Signer.sign_document(file_path, self.priv_key)

    def verify_file(self):
        """
        Opens file dialogs to select a document and its signature for verification.
        Verifies the selected document using the loaded public key.
        """
        if not self.pub_key:
            messagebox.showerror("Error", "Public key not loaded or generated.")
            return
        file_path = filedialog.askopenfilename(title="Select a file to verify")
        sig_path = filedialog.askopenfilename(title="Select the signature file", initialdir=SIGNATURES_DIR)
        if file_path and sig_path:
            Signer.verify_signature(file_path, sig_path, self.pub_key)

