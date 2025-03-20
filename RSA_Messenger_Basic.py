from cryptography.hazmat.primitives import hashes
from MessangerBasic.RSA_Generate_Keys import generate_rsa_keys  # Import the function

# Hash Message using SHA-256
def hash_message(message):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(message.encode())  # Convert string to bytes
    return digest.finalize()  # Returns 32-byte hash

# Sign Message
def sign_message(message, private_key):
    hashed = int.from_bytes(hash_message(message), byteorder="big")  # Convert hash to integer
    d, n = private_key  # Extract private key components
    return pow(hashed, d, n)  # RSA Signature: hash^d mod n

# Verify Signature
def verify_signature(message, signature, public_key):
    hashed = int.from_bytes(hash_message(message), byteorder="big")  # Hash message again
    e, n = public_key  # Extract public key components
    decrypted_hash = pow(signature, e, n)  # RSA Verification: signature^e mod n
    return decrypted_hash == hashed  # Check if the hashes match

# Main Execution
if __name__ == "__main__":
    public_key, private_key = generate_rsa_keys()  # Generate RSA keys
    message = input("\nEnter message to sign: ")
    
    signature = sign_message(message, private_key)  # Sign the message
    print(f"\n🔏 Signature: {signature}")

    is_valid = verify_signature(message, signature, public_key)  # Verify the signature
    print("\n✅ Signature is VALID!" if is_valid else "\n❌ Signature is INVALID!")
