from cryptography.fernet import Fernet

# These will be initialized using init_encryption
DECRYPTION_KEY = None
cipher = None

def init_encryption(decryption_key, fernet_key):
    global DECRYPTION_KEY, cipher
    DECRYPTION_KEY = decryption_key
    cipher = Fernet(fernet_key)

def encrypt_data(data):
    if cipher:
        return cipher.encrypt(data.encode()).decode()
    return "Encryption Failed"

def decrypt_data(encrypted_data, key):
    if key != DECRYPTION_KEY:
        return "Invalid Key"
    try:
        return cipher.decrypt(encrypted_data.encode()).decode()
    except:
        return "Decryption Failed"
