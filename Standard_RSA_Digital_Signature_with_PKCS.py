import hashlib

# Generate a large prime number
def generate_prime(bits=1024):
    from sympy import randprime
    return randprime(2**(bits-1), 2**bits)

# Generate RSA key pair (public and private keys)
def generate_rsa_keys():
    public_exponent = 65537  # Common public exponent
    prime_p, prime_q = generate_prime(), generate_prime()  # Generate two large primes
    modulus = prime_p * prime_q  # Modulus
    totient = (prime_p - 1) * (prime_q - 1)  # Euler's totient function
    private_exponent = pow(public_exponent, -1, totient)  # Compute modular inverse of e
    return (modulus, public_exponent, private_exponent)  # Return public (n, e) and private (n, d) keys

# Compute SHA-256 hash of a message
def sha256(message):
    return hashlib.sha256(message.encode()).digest()  # Returns 32-byte hash

# Apply PKCS#1 v1.5 padding to the message hash
def pkcs1_v1_5_pad(message_hash, modulus):
    encoded_message_length = (modulus.bit_length() + 7) // 8  # Length of the encoded message in bytes
    padding_bytes = b"\xff" * (encoded_message_length - len(message_hash) - 3)  # Padding bytes
    return int.from_bytes(b"\x00\x01" + padding_bytes + b"\x00" + message_hash, byteorder="big")

# Remove PKCS#1 v1.5 padding and extract the message hash
def pkcs1_v1_5_unpad(signature_as_int, modulus):
    encoded_message = signature_as_int.to_bytes((modulus.bit_length() + 7) // 8, byteorder="big")
    padding_end_index = encoded_message.index(b"\x00", 2)  # Find the end of the padding
    return encoded_message[padding_end_index + 1:]  # Extract and return the message hash

# Sign a message using the private key
def sign_message(message, private_key):
    modulus, private_exponent = private_key
    message_hash = sha256(message)  # Hash the message
    padded_message_hash = pkcs1_v1_5_pad(message_hash, modulus)  # Apply padding
    return pow(padded_message_hash, private_exponent, modulus)  # Signature = (padded_hash)^d mod n

# Verify a signature using the public key
def verify_signature(message, signature, public_key):
    modulus, public_exponent = public_key
    message_hash = sha256(message)  # Hash the original message
    decrypted_signature_as_int = pow(signature, public_exponent, modulus)  # Decrypt the signature
    recovered_message_hash = pkcs1_v1_5_unpad(decrypted_signature_as_int, modulus)  # Remove padding
    return recovered_message_hash == message_hash  # Compare hashes

# Main execution
if __name__ == "__main__":
    print("🔒 RSA Digital Signature with PKCS#1 v1.5 Padding")

    # Generate RSA key pair
    modulus, public_exponent, private_exponent = generate_rsa_keys()
    public_key = (modulus, public_exponent)
    private_key = (modulus, private_exponent)

    # Input message to sign
    message = input("\nEnter message to sign: ")

    # Sign the message
    signature = sign_message(message, private_key)
    print(f"\n🔏 Signature: {signature}")

    # Verify the signature
    is_signature_valid = verify_signature(message, signature, public_key)
    print("\n✅ Signature is VALID!" if is_signature_valid else "\n❌ Signature is INVALID!")
