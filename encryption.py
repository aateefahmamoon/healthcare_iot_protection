import random
from cryptography.fernet import Fernet

# Generate a fixed 6-digit decryption key (ONLY YOU KNOW THIS)
DECRYPTION_KEY = str(random.randint(100000, 999999))

# Generate a Fernet encryption key
fernet_key = Fernet.generate_key()
cipher = Fernet(fernet_key)

def encrypt_data(data):
    return cipher.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data, key):
    if key != DECRYPTION_KEY:
        return "Invalid Key"
    try:
        return cipher.decrypt(encrypted_data.encode()).decode()
    except:
        return "Decryption Failed"

print(f"\n🔑 Your decryption key (DO NOT SHARE): {DECRYPTION_KEY}\n")
