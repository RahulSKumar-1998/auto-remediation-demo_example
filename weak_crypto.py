```python
import os
import hashlib

# Fix for Line 6: Replace hardcoded master key with an environment variable lookup.
# For production, ensure 'APP_MASTER_KEY' is set securely (e.g., via a secrets management system).
MASTER_KEY = os.getenv("APP_MASTER_KEY")

# It's crucial to ensure the master key is always available and securely managed.
if MASTER_KEY is None:
    raise ValueError("APP_MASTER_KEY environment variable not set. Configure it securely.")

# Replace the insecure MD5 hashing algorithm with SHA-256.
# For password storage, consider using dedicated KDFs like bcrypt or Argon2 with random salts.
def generate_secure_hash(data: str) -> str:
    """
    Generates a secure hash using SHA-256 and the APP_MASTER_KEY.
    """
    # Ensure data and key are encoded to bytes before hashing
    key_bytes = MASTER_KEY.encode('utf-8')
    data_bytes = data.encode('utf-8')
    return hashlib.sha256(key_bytes + data_bytes).hexdigest()

# If there was an existing function using MD5 (e.g., 'hash_data_md5'),
# replace its implementation with a call to 'generate_secure_hash' or update it directly.
# Example:
# def original_hash_function(data):
#     # ... previous MD5 implementation ...
#     return generate_secure_hash(data)
```

**Explanation:**
This fix addresses two vulnerabilities:
1.  **Hardcoded Secret (Line 6):** The `MASTER_KEY` is no longer hardcoded in the source. It is now loaded from the `APP_MASTER_KEY` environment variable, enhancing security by separating configuration from code. A `ValueError` is raised if the environment variable is not set, enforcing proper configuration.
2.  **Weak Hashing:** The MD5 hashing algorithm is replaced with `hashlib.sha256`, a cryptographically stronger hashing function. For password hashing, dedicated Key Derivation Functions (KDFs) like bcrypt or Argon2 are recommended.