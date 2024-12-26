from db import get_user_by_username, create_user, insert_file, get_user_files, encrypt_file, generate_aes_key
from flask import Flask, render_template, request, redirect, url_for, flash, session,jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from datetime import datetime
import os
import base64

app = Flask(_name_)
app.secret_key = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:Pranathi.9@localhost:5432/personalDataVault'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Define upload settings
UPLOAD_FOLDER = 'uploaded_files'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

# Ensure the upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

class User(db.Model):
    _tablename_ = 'users'

    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    hashed_password = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class File(db.Model):
    _tablename_ = 'files'

    file_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    encrypted_file_path = db.Column(db.String(512), nullable=False)
    encrypted_aes_key = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Log(db.Model):
    _tablename_ = 'logs'

    log_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    action = db.Column(db.String(255), nullable=False)
    file_id = db.Column(db.Integer, db.ForeignKey('files.file_id'))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id)) 

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/vault', methods=['GET', 'POST'])
def vault():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = db.session.get(User, session['user_id'])
    files = File.query.filter_by(user_id=user.user_id).all()

    if request.method == 'POST':
        file = request.files['file']
        if file:
            try:
                # AES encryption: Generate AES key and IV
                aes_key = os.urandom(32)  # 256-bit AES key
                iv = os.urandom(16)       # 128-bit IV for AES-GCM mode

                # File path for storing the encrypted file
                encrypted_file_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{file.filename}.enc")

                # Encrypt file with AES
                cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=default_backend())
                encryptor = cipher.encryptor()
                ciphertext = encryptor.update(file.read()) + encryptor.finalize()

                # Write IV, ciphertext, and tag to the encrypted file
                with open(encrypted_file_path, 'wb') as enc_file:
                    enc_file.write(iv)  # Write IV
                    enc_file.write(ciphertext)  # Write ciphertext
                    enc_file.write(encryptor.tag)  # Write authentication tag

                # Encrypt the AES key with RSA public key
                encrypted_aes_key = encrypt_aes_key_with_rsa(user.public_key, aes_key)

                # Save encrypted file details to the database
                new_file = File(
                    user_id=user.user_id,
                    original_filename=file.filename,
                    encrypted_file_path=encrypted_file_path,
                    encrypted_aes_key=base64.b64encode(encrypted_aes_key).decode('utf-8')
                )
                db.session.add(new_file)
                db.session.commit()

                # Log the action
                new_log = Log(
                    user_id=user.user_id,
                    action="File uploaded",
                    file_id=new_file.file_id
                )
                db.session.add(new_log)
                db.session.commit()

                flash('File uploaded and encrypted successfully!', 'success')
            except Exception as e:
                flash(f"Error during file upload: {e}", 'danger')

    return render_template('vault.html', files=files)

@app.route('/view_file/<int:file_id>', methods=['GET'])
def view_file(file_id):
    try:
        user = db.session.get(User, session.get('user_id'))
        file = db.session.get(File, file_id)

        if not file or file.user_id != user.user_id:
            return jsonify({'message': 'File not found or unauthorized access.'}), 404

        # Load the private key 
        with open(private_key_path, 'rb') as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )

        # Decrypt AES key using RSA private key
        encrypted_aes_key = base64.b64decode(file.encrypted_aes_key)
        aes_key = private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Decrypt file
        with open(file.encrypted_file_path, 'rb') as enc_file:
            iv = enc_file.read(16)  # First 16 bytes are the IV
            ciphertext = enc_file.read()[:-16]  # Read everything except the last 16 bytes (authentication tag)
            
            # Seek to the last 16 bytes (authentication tag)
            enc_file.seek(-16, os.SEEK_END)  # Move pointer to the last 16 bytes
            tag = enc_file.read(16)  # Read the tag



            cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

        # Send the decrypted file for download
        response = app.response_class(decrypted_data, mimetype='application/octet-stream')
        response.headers['Content-Disposition'] = f'attachment; filename={file.original_filename}'
        return response

    except Exception as e:
        return jsonify({'message': 'An error occurred during file decryption.', 'error': str(e)}), 500

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        print('inside login')
        print('user: ', user)
        print('password: ', password)
        if user and check_password_hash(user.hashed_password, password):
            print('inside if')
            session['user_id'] = user.user_id
            flash('Login successful!', 'success')
            return redirect(url_for('vault'))
        else:
            flash("Invalid username or password!", 'danger')

    return render_template('login.html')

private_key_path = "D:/private_key.pem" 
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form.get('confirm_password')

        # Load the private key and generate public key
        public_key = load_private_key_and_generate_public_key(private_key_path)

        if password != confirm_password:
            flash("Passwords do not match. \nPlease try again.", "error")
            return redirect(url_for('register'))

        if get_user_by_username(username):
            flash("Username already exists!", 'danger')
            return redirect(url_for('register'))
        
        if public_key:
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

            new_user = User(username=username, public_key=public_key, hashed_password=hashed_password)
            db.session.add(new_user)
            db.session.commit()

            flash('User registered successfully!', 'success')
            return redirect(url_for('login'))
        else:
            flash('Failed to register user. Check your private key.', 'danger')

    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    # logout_user()
    session.pop('user_id', None)
    flash("You have been logged out.", 'info')
    return redirect(url_for('login'))

def load_private_key_and_generate_public_key(private_key_path):
    try:
        with open(private_key_path, 'rb') as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None
            )

        public_key = private_key.public_key()
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        return public_key_pem
    except Exception as e:
        print(f"Error loading private key: {e}")
        return None

def encrypt_aes_key_with_rsa(public_key_pem, aes_key):
    public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'), backend=default_backend())
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_aes_key

if _name_ == '_main_':
    app.run(debug=True)