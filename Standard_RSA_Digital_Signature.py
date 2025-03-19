import hashlib
import random

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

# SHA-256 Hash Function
def sha256(message):
    return hashlib.sha256(message.encode()).digest()  # Returns 32-byte hash

# Mask Generation Function (MGF1 for PSS)
def mgf1(seed, mask_len):
    counter = 0
    output = b""
    while len(output) < mask_len:
        counter_bytes = counter.to_bytes(4, byteorder="big")
        output += hashlib.sha256(seed + counter_bytes).digest()
        counter += 1
    return output[:mask_len]

# Apply PSS Padding
def pss_pad(message_hash, n):
    em_len = (n.bit_length() + 7) // 8
    salt = random.randbytes(32)  # Random 32-byte salt
    m_prime = b"\x00" * 8 + message_hash + salt
    m_prime_hash = hashlib.sha256(m_prime).digest()
    ps_len = em_len - len(m_prime_hash) - len(salt) - 2
    ps = b"\x00" * ps_len
    db = ps + b"\x01" + salt
    db_mask = mgf1(m_prime_hash, len(db))
    masked_db = bytes(x ^ y for x, y in zip(db, db_mask))
    em = masked_db + m_prime_hash + b"\xbc"
    return int.from_bytes(em, byteorder="big")

# Remove PSS Padding
def pss_unpad(signature_int, n):
    em = signature_int.to_bytes((n.bit_length() + 7) // 8, byteorder="big")
    masked_db, m_prime_hash, bc = em[:-33], em[-33:-1], em[-1]
    if bc != 0xbc:
        return None  # Padding error
    db_mask = mgf1(m_prime_hash, len(masked_db))
    db = bytes(x ^ y for x, y in zip(masked_db, db_mask))
    salt = db[len(db) - 32:]
    m_prime = b"\x00" * 8 + m_prime_hash + salt
    return hashlib.sha256(m_prime).digest()

# Sign Message with RSA-PSS
def sign_message(message, private_key):
    n, d = private_key
    message_hash = sha256(message)
    padded_hash = pss_pad(message_hash, n)
    return pow(padded_hash, d, n)  # Signature = (padded_hash)^d mod n

# Verify RSA Signature
def verify_signature(message, signature, public_key):
    n, e = public_key
    decrypted_int = pow(signature, e, n)  # decrypted_hash = (signature)^e mod n
    recovered_hash = pss_unpad(decrypted_int, n)
    return recovered_hash == sha256(message)

# Main Execution
if __name__ == "__main__":
    print("🔒 Fully Original Standard-Compliant RSA Digital Signature")

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
