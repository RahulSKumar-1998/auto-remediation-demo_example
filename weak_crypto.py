import hashlib

def hash_password(password):
    # VULNERABILITY: Weak Hashing Algorithm
    # MD5 is considered broken and insecure for password hashing.
    hasher = hashlib.md5()
    hasher.update(password.encode('utf-8'))
    return hasher.hexdigest()

def store_key(key):
    # VULNERABILITY: Hardcoded Secret (just to be sure we have something reliable)
    master_key = "12345-ABCDE-SECRET"
    print(f"Stored with {master_key}")
