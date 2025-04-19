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
    return hashlib.sha256(message.encode()).hexdigest()

# Sign Message (RSA Signature)
def sign_message(message, private_key):
    n, d = private_key
    hashed = int(hash_message(message), 16)
    return pow(hashed, d, n)  # Signature = hash^d mod n

# Verify Signature
def verify_signature(message, signature, public_key):
    n, e = public_key
    hashed = int(hash_message(message), 16)
    decrypted_hash = pow(signature, e, n)  # Verify = signature^e mod n
    return decrypted_hash == hashed, hex(decrypted_hash)

# Main Execution
if __name__ == "__main__":
    print("🔒 Standard RSA Digital Signature Implementation")
    input("")

    # Generate RSA Key Pair
    n, e, d = generate_rsa_keys()
    public_key = (n, e)
    private_key = (n, d)
    print("\n🔑 RSA Key Pair Generated!")
    input("")

    print(f"\nPublic Key: {public_key}")
    input("")

    print(f"\nPrivate Key: {private_key}")
    input("")

    # First message with detailed explanation
    message = "Message 1: Hello, RSA!"
    print(f"\nMessage: {message}")
    input("")

    # Hashing the message
    hashed_message = hash_message(message)
    print(f"\nHashed Message (SHA-256 in Hex): {hashed_message}")
    input("")

    # Signing the message
    signature = sign_message(message, private_key)
    print(f"\n🔏 Signature (Signed Hash in Hex): {hex(signature)}")
    input("")

    # Verifying the signature
    is_valid, decrypted_hash = verify_signature(message, signature, public_key)
    print(f"\nReceived Message Hash (Hex): {hashed_message}")
    print(f"Decrypted Hash (from Signature in Hex): {decrypted_hash}")
    print("\n✅ Signature is VALID!" if is_valid else "\n❌ Signature is INVALID!")
    input("")

    # Remaining messages with test cases
    messages = [
        "Message 2: 1234567890",  # Numbers
        "Message 3: !@#$%^&*()",  # Symbols
        "Message 4: The quick brown fox jumps over the lazy dog.",  # Full sentence
        "Message 5: こんにちは世界",  # Unicode (Japanese)
        "Message 6: 🚀🌟✨🔥",  # Emojis
    ]

    for i, message in enumerate(messages, start=2):
        print(f"\nMessage: {message}")
        input("")

        # Signing
        signature = sign_message(message, private_key)
        print(f"\n🔏 Signature (in Hex): {hex(signature)}")
        input("")

        # Verification
        is_valid, _ = verify_signature(message, signature, public_key)
        print("\n✅ Signature is VALID!" if is_valid else "\n❌ Signature is INVALID!")
        if i < len(messages) + 1:
            input("")