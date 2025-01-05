import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from tkinter import messagebox

# Default directory for storing signatures
SIGNATURES_DIR = "signatures"
os.makedirs(SIGNATURES_DIR, exist_ok=True)


class Signer:
    @staticmethod
    def sign_document(document_path, private_key):
        """
        Signs a document using the provided private key.
        Saves the signature to a file and shows a success message.
        """
        # Read the document data
        with open(document_path, 'rb') as file:
            document_data = file.read()

        # Generate the signature
        signature = private_key.sign(
            document_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        # Save the signature to a file
        signature_path = os.path.join(SIGNATURES_DIR, os.path.basename(document_path) + ".sig")
        with open(signature_path, 'wb') as sig_file:
            sig_file.write(signature)

        messagebox.showinfo("Success", f"Document signed successfully.\nSignature saved at: {signature_path}")
        return signature

    @staticmethod
    def verify_signature(document_path, signature_path, public_key):
        """
        Verifies the signature of a document using the provided public key.
        Shows a success or error message depending on the verification result.
        """
        # Read the document data
        with open(document_path, 'rb') as file:
            document_data = file.read()

        # Read the signature
        with open(signature_path, 'rb') as sig_file:
            signature = sig_file.read()

        try:
            # Verify the signature
            public_key.verify(
                signature,
                document_data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            messagebox.showinfo("Success", "The signature is valid.")
            return True
        except Exception as e:
            messagebox.showerror("Error", f"The signature is invalid: {e}")
            return False
