import re
import secrets
import string
import os
from cryptography.fernet import Fernet
import hashlib
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

#----------------------------------------------------------------

def get_encryption_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600000,
    )
    import base64
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def hash_password(password: str, salt: bytes) -> str:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600000,
    )
    key = kdf.derive(password.encode())
    return key.hex()

def save_master_password(password: str, path: Path):
    salt = os.urandom(16)
    hashed = hash_password(password, salt)
    with open(path / "master.hash", "w") as f:
        f.write(f"{salt.hex()}:{hashed}")

def verify_master_password(password: str, path: Path) -> bool:
    hash_file = path / "master.hash"
    if not hash_file.exists():
        return False
    with open(hash_file, "r") as f:
        stored_data = f.read()
    try:
        salt_hex, stored_hash = stored_data.split(":")
        salt = bytes.fromhex(salt_hex)
        current_hash = hash_password(password, salt)
        return current_hash == stored_hash
    except ValueError:
        return False

def check_password(password: str) -> int:
    score = 0
    if len(password) >= 8: score += 1
    if re.search(r"[a-z]", password): score += 1
    if re.search(r"[A-Z]", password): score += 1
    if re.search(r"[0-9]", password): score += 1
    if re.search(r"[!@#$%^&*()_+]", password): score += 1
    return score

#----------------------------------------------------------------

def generate_password(length=16):
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()_+"
    while True:
        password = ''.join(secrets.choice(alphabet) for _ in range (length))
        if check_password(password) == 5:
            return password

def load_or_generate_key(key_path: str):
    if not os.path.exists(key_path):
        key = Fernet.generate_key()
        with open(key_path, "wb") as key_file:
            key_file.write(key)
        return key
    
    with open(key_path, "rb") as key_file:
        return key_file.read()

def encrypt_password(password: str, key: bytes) -> str:
    f = Fernet(key)
    return f.encrypt(password.encode()).decode()

def decrypt_password(encrypted_password: str, key: bytes) -> str:
    f = Fernet(key)
    return f.decrypt(encrypted_password.encode()).decode()