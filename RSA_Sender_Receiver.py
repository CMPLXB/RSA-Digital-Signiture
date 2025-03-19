import socket
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes

# Generate RSA keys
def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

# Hash Message
def hash_message(message):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(message.encode())
    return digest.finalize()

# Sign Message (No Padding, Hex Output)
def sign_message(message, private_key):
    hashed = int.from_bytes(hash_message(message), byteorder="big")
    n = private_key.public_key().public_numbers().n
    d = private_key.private_numbers().d
    signature = pow(hashed, d, n)
    return signature.to_bytes((signature.bit_length() + 7) // 8, byteorder="big").hex()

# Verify Signature (No Padding)
def verify_signature(message, signature_hex, public_key):
    hashed = int.from_bytes(hash_message(message), byteorder="big")
    n = public_key.public_numbers().n
    e = public_key.public_numbers().e
    signature = int.from_bytes(bytes.fromhex(signature_hex), byteorder="big")
    decrypted_hash = pow(signature, e, n)
    return decrypted_hash == hashed

# Send Message
def send_message():
    private_key, public_key = generate_rsa_keys()
    message = input("\nEnter message to sign: ")
    signature_hex = sign_message(message, private_key)

    print(f"\n📨 Sending Message: {message}")
    print(f"🔏 Signature (Hex): {signature_hex}")

    sender_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sender_socket.connect(("127.0.0.1", 12345))
        data_to_send = f"{message}||{signature_hex}||{public_key.public_numbers().n}||{public_key.public_numbers().e}"
        sender_socket.sendall(data_to_send.encode())
        sender_socket.close()
        print("\n✅ Message Sent!")
    except ConnectionRefusedError:
        print("\n❌ Receiver is not running!")

# Receive and Verify Message
def receive_message():
    receiver_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    receiver_socket.bind(("127.0.0.1", 12345))
    receiver_socket.listen(1)
    print("\nReceiver is waiting for a message...")

    conn, _ = receiver_socket.accept()
    data = conn.recv(4096).decode()
    conn.close()

    message, signature_hex, n, e = data.split("||")
    n, e = int(n), int(e)
    public_key = rsa.RSAPublicNumbers(e, n).public_key()

    print(f"\n📩 Received Message: {message}")
    print(f"🔏 Received Signature (Hex): {signature_hex}")

    is_valid = verify_signature(message, signature_hex, public_key)
    print("\n✅ Signature is VALID!" if is_valid else "\n❌ Signature is INVALID!")

# Main Menu
if __name__ == "__main__":
    print("🔒 RSA Secure Messenger 🔒")
    print("1️⃣ Send a Signed Message")
    print("2️⃣ Receive and Verify a Signed Message")
    
    choice = input("\nChoose an option (1 or 2): ")
    
    if choice == "1":
        send_message()
    elif choice == "2":
        receive_message()
    else:
        print("\n❌ Invalid choice. Please restart the program.")
