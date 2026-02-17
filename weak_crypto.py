from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

def encrypt_data(data, key):
    # VULNERABILITY: ECB mode is insecure
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()

key = os.urandom(32)
data = b"Secret Message"
encrypted = encrypt_data(data, key)
print(encrypted)
# Trigger Scan
