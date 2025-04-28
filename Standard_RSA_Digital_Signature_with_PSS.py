import hashlib
import os

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

# SHA-256 hash function
def sha256(data):
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).digest()

# MGF1 Mask Generation Function (based on SHA-256)
def mgf1(seed, length):
    result = b""
    counter = 0
    while len(result) < length:
        C = counter.to_bytes(4, byteorder='big')
        result += sha256(seed + C)
        counter += 1
    return result[:length]

# PSS Encode for signature generation
def pss_encode(message, salt_length=32, modulus_bit_length=2048):
    # Calculate emLen (encoded message length in bytes)
    emLen = (modulus_bit_length + 7) // 8
    
    # Hash the message
    mHash = sha256(message)
    
    # Generate salt
    salt = os.urandom(salt_length)
    
    # Create M' = (8 zeros || mHash || salt)
    M_prime = b'\x00' * 8 + mHash + salt
    
    # Calculate H = hash(M')
    H = sha256(M_prime)
    
    # Calculate DB = PS || 0x01 || salt
    PS_length = emLen - salt_length - len(H) - 2
    DB = b'\x00' * PS_length + b'\x01' + salt
    
    # Calculate dbMask = MGF(H, emLen - hLen - 1)
    dbMask = mgf1(H, emLen - len(H) - 1)
    
    # Calculate maskedDB = DB ⊕ dbMask
    maskedDB = bytes(a ^ b for a, b in zip(DB, dbMask))
    
    # Set the leftmost bits in the leftmost byte to zero
    # (8 * emLen - modulus_bit_length + 1 bits)
    bits_to_clear = 8 * emLen - modulus_bit_length + 1
    if bits_to_clear > 0 and bits_to_clear <= 8:
        maskedDB = bytes([maskedDB[0] & (0xff >> bits_to_clear)]) + maskedDB[1:]
    
    # Construct encoded message: maskedDB || H || 0xbc
    EM = maskedDB + H + b'\xbc'
    
    return EM

# PSS Verify for signature verification
def pss_verify(message, EM, salt_length=32, modulus_bit_length=2048):
    # Calculate emLen (encoded message length in bytes)
    emLen = (modulus_bit_length + 7) // 8
    
    # Hash the message
    mHash = sha256(message)
    
    # Check if the rightmost byte is 0xbc
    if EM[-1] != 0xbc:
        return False
    
    # Split the encoded message
    hLen = len(sha256(b''))  # Length of hash output
    maskedDB = EM[:emLen - hLen - 1]
    H = EM[emLen - hLen - 1:-1]
    
    # Check leftmost bits of maskedDB
    bits_to_clear = 8 * emLen - modulus_bit_length + 1
    if bits_to_clear > 0 and bits_to_clear <= 8:
        if maskedDB[0] >> (8 - bits_to_clear) != 0:
            return False
    
    # Calculate dbMask = MGF(H, emLen - hLen - 1)
    dbMask = mgf1(H, emLen - hLen - 1)
    
    # Calculate DB = maskedDB ⊕ dbMask
    DB = bytes(a ^ b for a, b in zip(maskedDB, dbMask))
    
    # Clear leftmost bits if needed
    if bits_to_clear > 0 and bits_to_clear <= 8:
        DB = bytes([DB[0] & (0xff >> bits_to_clear)]) + DB[1:]
    
    # Check the padding pattern in DB
    one_index = 0
    while one_index < len(DB) and DB[one_index] == 0:
        one_index += 1
        
    if one_index >= len(DB) or DB[one_index] != 1:
        return False
    
    # Extract the salt
    salt = DB[one_index+1:]
    
    # Create M' = (8 zeros || mHash || salt)
    M_prime = b'\x00' * 8 + mHash + salt
    
    # Verify H = hash(M')
    H_prime = sha256(M_prime)
    
    return H == H_prime

# Sign Message with PSS padding
def sign_message(message, private_key):
    n, d = private_key
    # PSS encode the message
    encoded = pss_encode(message, modulus_bit_length=n.bit_length())
    # Convert to integer
    encoded_int = int.from_bytes(encoded, byteorder='big')
    # Apply RSA signature operation
    signature = pow(encoded_int, d, n)
    return signature

# Verify Signature with PSS padding
def verify_signature(message, signature, public_key):
    n, e = public_key
    # Apply RSA verification operation
    encoded_int = pow(signature, e, n)
    # Convert to bytes
    encoded = encoded_int.to_bytes((n.bit_length() + 7) // 8, byteorder='big')
    # Verify PSS padding
    return pss_verify(message, encoded, modulus_bit_length=n.bit_length())

# Main Execution
if __name__ == "__main__":
    print("🔒 RSA Digital Signature with PSS Padding")

    # Generate RSA Key Pair
    n, e, d = generate_rsa_keys()
    public_key = (n, e)
    private_key = (n, d)

    # User inputs a message
    message = input("\nEnter message to sign: ")

    # Signing with PSS padding
    signature = sign_message(message, private_key)
    print(f"\n🔏 Signature: {signature}")

    # Verification with PSS padding
    is_valid = verify_signature(message, signature, public_key)
    print("\n✅ Signature is VALID!" if is_valid else "\n❌ Signature is INVALID!")
