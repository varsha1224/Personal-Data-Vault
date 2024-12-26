# Personal-Data-Vault
The Personal Data Vault is a Flask-based web application designed to securely store and manage encrypted files. Users can register, log in, upload files, and retrieve them after decryption. The application uses AES encryption for file content and RSA encryption to encrypt the AES keys. The app leverages PostgreSQL for persistent storage of users, files, and logs.

**Features**

User Registration and Authentication: Users can register and log in with secure passwords.

File Upload and Encryption: Files uploaded by users are encrypted with AES before being stored.

RSA Encryption for AES Keys: AES keys used to encrypt the files are encrypted with the user's RSA public key.

File Decryption: Authorized users can decrypt and download their files.

Action Logging: All actions (e.g., file uploads) are logged for auditing purposes.

**Installation**

**Prerequisites**

Python 3.x

PostgreSQL database

pip for installing Python packages

Setting Up the Environment

Create and activate a virtual environment:

python3 -m venv venv

source venv/bin/activate  # On Windows, use `venv\Scripts\activate`

Install the required Python packages:

pip install -r requirements.txt

Set up the PostgreSQL database:

Ensure you have PostgreSQL installed and running.

Create a new database (e.g., personalDataVault).

Initialize the database schema:

You can manually create the tables in PostgreSQL or use an ORM tool to automatically generate them. The schema includes three main tables: users, files, and logs.

Set up Flask secret keys and encryption:

Update private_key_path in the app.py file to point to the private key used for generating public keys during registration.


**Endpoints**
/login (GET, POST)

Purpose: User login.

Request Body:

username: The user's username.

password: The user's password.

Response: Redirects to the vault page on successful login, or displays an error message.

/register (GET, POST)

Purpose: User registration.

Request Body:

username: The username for the new account.

password: The user's password.

confirm_password: Confirms the password.

Response: Redirects to the login page after successful registration, or displays an error message.

/vault (GET, POST)

Purpose: Displays the user's files and allows uploading new files.

Request Body (POST):

file: The file to upload.

Response: Displays the user's files and a success message for successful uploads.

/view_file/<file_id> (GET)

Purpose: Decrypt and provide the requested file for download.

Response: Returns a JSON object with a path to the decrypted file.

/logout (GET)

Purpose: Logs out the current user and redirects to the login page.

File Structure

personal-data-vault/

│

├── app.py                # Flask app containing routes and main logic

├── db.py                 # Database interactions and utility functions

├── requirements.txt      # Python dependencies

├── templates/            # HTML templates (e.g., login, register, vault)

│   ├── login.html

│   ├── register.html

│   └── vault.html

├── static/               # Static assets (CSS files)

├── uploaded_files/       # Folder where encrypted files are stored

└── downloads/            # Folder for decrypted files to be downloaded

**Cryptography Details**

AES Encryption: Files are encrypted using AES in GCM mode (256-bit key).

RSA Encryption: AES keys are encrypted using the user's RSA public key (OAEP padding with SHA-256).

AES Encryption:

The AES key is randomly generated.

The file is encrypted using the AES key and the ciphertext is saved along with an IV and authentication tag in the encrypted file.

RSA Encryption:

The AES key is encrypted using the RSA public key of the user during file upload.

The encrypted AES key is stored in the database along with the file metadata.

**Security Considerations**

Private Key Storage: Ensure that the private keys used for decryption are stored securely.

Session Management: The application uses Flask’s session management for user authentication.

File Integrity: The use of AES-GCM ensures both confidentiality and integrity of the files.

**Troubleshooting**

Database Connection Issues: Make sure that PostgreSQL is running and the DB_CONFIG credentials are correct.

File Upload Errors: Check that the file types are allowed (txt, pdf, png, jpg, jpeg, gif).

Decryption Errors: Ensure the correct private key is being used for decryption.

**Future Enhancements**

Multiple Users: Currently, only one user can upload and manage files. Implement a multi-user system for sharing files.

Improved Error Handling: Enhance error messages and handling for more edge cases.

File Sharing: Allow users to share encrypted files with others.

Logging Improvements: Enhance the log management system for auditing purposes.
