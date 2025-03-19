from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes

# Generate RSA keys
def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

# Hash Message using SHA-256
def hash_message(message):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(message.encode())  # Convert string to bytes
    return digest.finalize()  # Returns 32-byte hash

# Sign Message
def sign_message(message, private_key):
    hashed = int.from_bytes(hash_message(message), byteorder="big")  # Convert hash to integer
    n = private_key.public_key().public_numbers().n
    d = private_key.private_numbers().d
    return pow(hashed, d, n)  # RSA Signature: hash^d mod n

# Verify Signature
def verify_signature(message, signature, public_key):
    hashed = int.from_bytes(hash_message(message), byteorder="big")  # Hash message again
    n = public_key.public_numbers().n
    e = public_key.public_numbers().e
    decrypted_hash = pow(signature, e, n)  # RSA Verification: signature^e mod n
    return decrypted_hash == hashed  # Check if the hashes match

# Main Execution
if __name__ == "__main__":
    private_key, public_key = generate_rsa_keys()
    message = input("\nEnter message to sign: ")
    
    signature = sign_message(message, private_key)
    print(f"\n🔏 Signature: {signature}")

    is_valid = verify_signature(message, signature, public_key)
    print("\n✅ Signature is VALID!" if is_valid else "\n❌ Signature is INVALID!")
