from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

# Generate RSA keys
def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

# Sign Message (Using SHA-256 and PSS padding)
def sign_message(message, private_key):
    return private_key.sign(
        message.encode(),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

# Verify Signature
def verify_signature(message, signature, public_key):
    try:
        public_key.verify(
            signature,
            message.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except:
        return False

# Main Execution
if __name__ == "__main__":
    private_key, public_key = generate_rsa_keys()
    message = input("\nEnter message to sign: ")
    
    signature = sign_message(message, private_key)
    print(f"\n🔏 Signature: {signature.hex()}")  # Display in hex format

    is_valid = verify_signature(message, signature, public_key)
    print("\n✅ Signature is VALID!" if is_valid else "\n❌ Signature is INVALID!")
