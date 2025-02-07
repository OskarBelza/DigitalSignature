### **1. Introduction**
The application is designed for digitally signing documents and verifying their signatures using asymmetric cryptography. The key role in the application is played by RSA keys, which are generated, saved to files, and read during the program's execution. Users can dynamically provide a password to secure the private key.

---

### **2. Main Features**

1. **Generating an RSA key pair**
2. **Saving keys to files** (with encryption of the private key)
3. **Loading keys from files** (with decryption of the private key)
4. **Signing a document** with a private key
5. **Verifying a signature** with a public key

---

### **3. Application Workflow**

#### **3.1 Generating an RSA Key Pair**

1. The user selects the "Generate Key Pair" option.
2. The application displays a dialog box prompting the user to enter a password, which will be used to encrypt the private key.
3. After entering the password, the application:
   - Generates an RSA key pair using the function:
     ```python
     private_key = rsa.generate_private_key(
         public_exponent=65537,
         key_size=2048,
         backend=default_backend()
     )
     public_key = private_key.public_key()
     ```
     - **`public_exponent=65537`** – Standard public exponent value used in RSA cryptography.
     - **`key_size=2048`** – RSA key size in bits, ensuring a high level of security.

4. The generated keys are saved to files in the `keys/` directory:
   - The private key is encrypted using the provided password:
     ```python
     private_key.private_bytes(
         encoding=serialization.Encoding.PEM,
         format=serialization.PrivateFormat.PKCS8,
         encryption_algorithm=serialization.BestAvailableEncryption(password)
     )
     ```
     - **`serialization.BestAvailableEncryption(password)`** – Uses the best available encryption algorithm for securing the private key with the provided password.

5. The public key is saved in PEM format without encryption.
6. The application displays a message confirming the successful key generation and storage.

---

#### **3.2 Loading an RSA Key Pair**

1. The user selects the "Load Key Pair" option.
2. The application displays a dialog box prompting the user to enter the password used to encrypt the private key.
3. After entering the password, the application loads the keys from the files:
   - The private key is decrypted using the function:
     ```python
     private_key = serialization.load_pem_private_key(
         priv_file.read(),
         password=password,
         backend=default_backend()
     )
     ```
   - The public key is loaded without requiring a password.
4. If the keys are successfully loaded, the application displays a confirmation message.

---

#### **3.3 Signing a Document**

1. The user selects the "Sign Document" option and chooses the file to sign.
2. The application loads the file content and generates a digital signature using the private key:
   ```python
   signature = private_key.sign(
       document_data,
       padding.PSS(
           mgf=padding.MGF1(hashes.SHA256()),
           salt_length=padding.PSS.MAX_LENGTH
       ),
       hashes.SHA256()
   )
   ```
   - **`padding.PSS`** – Uses the Probabilistic Signature Scheme (PSS), providing higher security than older padding methods.
   - **`hashes.SHA256()`** – The SHA-256 hash algorithm is used to compute the message digest before signing.

3. The signature is saved in a `.sig` file in the `signatures/` directory.
4. The application displays a message confirming the document has been successfully signed.

---

#### **3.4 Verifying a Signature**

1. The user selects the "Verify Signature" option and chooses the document and its corresponding signature file.
2. The application loads the document and the signature, then verifies it using the public key:
   ```python
   public_key.verify(
       signature,
       document_data,
       padding.PSS(
           mgf=padding.MGF1(hashes.SHA256()),
           salt_length=padding.PSS.MAX_LENGTH
       ),
       hashes.SHA256()
   )
   ```
3. If the signature is valid, the application displays a confirmation message.
4. If the signature is invalid or an error occurs, the application displays a verification failure message.

---

### **4. Important Cryptographic Functions Used**

1. **`rsa.generate_private_key`**
   - Generates an RSA key pair (private and public keys).
   - Parameters:
     - `public_exponent=65537` – Public exponent value.
     - `key_size=2048` – Key length in bits.

2. **`private_key.sign`**
   - Creates a digital signature for data using the private key.
   - Uses the PSS padding scheme and SHA-256 hash algorithm.

3. **`public_key.verify`**
   - Verifies the validity of a digital signature using the public key.
   - Uses the same padding scheme and hash algorithm as during signing.

4. **`serialization.BestAvailableEncryption`**
   - Encrypts the private key with a password.
   - Provides the highest available level of security.

5. **`serialization.load_pem_private_key`**
   - Reads and decrypts a private key from a PEM file using a provided password.

6. **`serialization.load_pem_public_key`**
   - Reads a public key from a PEM file.

---

### **5. Conclusion**
The application ensures document security through asymmetric cryptography and advanced signing and verification methods. Encrypting the private key with a password guarantees that only authorized users can sign documents.

