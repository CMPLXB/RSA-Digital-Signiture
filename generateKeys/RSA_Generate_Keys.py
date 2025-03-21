import random

# Function to check if a number is prime (basic primality test)
def is_prime(n, k=10):  # Miller-Rabin Primality Test
    if n < 2:
        return False
    for _ in range(k):
        a = random.randint(2, n - 1)
        if pow(a, n - 1, n) != 1:
            return False
    return True

# Function to generate a large prime number
def generate_prime(bits=512):
    while True:
        num = random.getrandbits(bits) | (1 << bits - 1) | 1  # Ensure it's odd and has `bits` length
        if is_prime(num):
            return num

# Function to compute GCD
def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

# Function to compute modular inverse using Extended Euclidean Algorithm
def mod_inverse(e, phi):
    a, b, x0, x1 = e, phi, 0, 1
    while a:
        q, b, a = b // a, a, b % a
        x0, x1 = x1 - q * x0, x0
    return x1 + phi if x1 < 0 else x1

# RSA Key Generation
def generate_rsa_keys():
    # Step 1: Generate two large primes p and q
    p = generate_prime(512)
    q = generate_prime(512)

    # Step 2: Compute n = p * q
    n = p * q

    # Step 3: Compute Euler's totient function φ(n)
    phi = (p - 1) * (q - 1)

    # Step 4: Choose public exponent e (commonly 65537)
    e = 65537
    while gcd(e, phi) != 1:
        e = random.randrange(2, phi)  # Pick another e if gcd(e, phi) ≠ 1

    # Step 5: Compute private exponent d (modular inverse of e mod φ(n))
    d = mod_inverse(e, phi)

    # Return the key pair
    return (e, n), (d, n)  # Public and Private keys

# Generate RSA key pairs
public_key, private_key = generate_rsa_keys()
print("Public Key:", public_key)
print("Private Key:", private_key)