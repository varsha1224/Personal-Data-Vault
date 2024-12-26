# Updated db.py
import psycopg2
from psycopg2 import sql
import os
from Crypto.Cipher import AES # type: ignore
from Crypto.Util.Padding import pad, unpad # type: ignore
from base64 import b64encode, b64decode

# Database connection setup (replace with your database credentials)
DB_CONFIG = {
    'dbname': 'dataVault',
    'user': 'postgres',
    'password': 'krishna',
    'host': 'localhost',
    'port': '5432'
}

def get_db_connection():
    conn = psycopg2.connect(host=DB_CONFIG['host'], port=DB_CONFIG['port'], database=DB_CONFIG['dbname'], user=DB_CONFIG['user'], password=DB_CONFIG['password'])
    return conn

def get_user_by_username(username):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    return user

def create_user(user_id, username, password, created_at):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO users (user_id, username, password, created_at) VALUES (%s, %s, %s, %s)",
        (user_id, username, password, created_at)
    )
    conn.commit()
    cursor.close()
    conn.close()

def insert_file(user_id, original_filename, encrypted_file_path, encrypted_aes_key):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO files (user_id, original_filename, encrypted_file_path, encrypted_aes_key) VALUES (%s, %s, %s, %s)",
        (user_id, original_filename, encrypted_file_path, encrypted_aes_key)
    )
    conn.commit()
    cursor.close()
    conn.close()

def get_user_files(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM files WHERE user_id = %s", (user_id,))
    files = cursor.fetchall()
    cursor.close()
    conn.close()
    return files

def encrypt_file(file_data, key):
    cipher = AES.new(key, AES.MODE_CBC)
    encrypted_data = cipher.encrypt(pad(file_data, AES.block_size))
    return cipher.iv + encrypted_data  # Store IV + encrypted data

def generate_aes_key():
    return os.urandom(32)