import hashlib

# Generate large prime numbers
def generate_prime(bits=1024):
    from sympy import randprime
    return randprime(2**(bits-1), 2**bits)

# Generate RSA Keys
def generate_rsa_keys():
    e = 65537  # Common public exponent
    p, q = generate_prime(), generate_prime()
    n = p * q
    phi = (p-1) * (q-1)
    d = pow(e, -1, phi)  # Compute modular inverse
    return (n, e, d)  # Public (n, e), Private (n, d)

# Hash Message using SHA-256
def hash_message(message):
    return int(hashlib.sha256(message.encode()).hexdigest(), 16)

# Sign Message (RSA Signature)
def sign_message(message, private_key):
    n, d = private_key
    hashed = hash_message(message)
    return pow(hashed, d, n)  # Signature = hash^d mod n

# Verify Signature
def verify_signature(message, signature, public_key):
    n, e = public_key
    hashed = hash_message(message)
    decrypted_hash = pow(signature, e, n)  # decrypted = signature^e mod n
    return decrypted_hash == hashed

# Main Execution
if __name__ == "__main__":
    print("🔒 Standard RSA Digital Signature Implementation")

    # Generate RSA Key Pair
    n, e, d = generate_rsa_keys()
    public_key = (n, e)
    private_key = (n, d)

    # User inputs a message
    message = input("\nEnter message to sign: ")

    # Signing
    signature = sign_message(message, private_key)
    print(f"\n🔏 Signature: {signature}")

    # Verification
    is_valid = verify_signature(message, signature, public_key)
    print("\n✅ Signature is VALID!" if is_valid else "\n❌ Signature is INVALID!")
