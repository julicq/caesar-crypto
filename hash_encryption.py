import hashlib
import rsa

# Hash function
def hash_data(data):
    """
    Returns the SHA-256 hash of the input data.
    :param data: The data to be hashed.
    :return: The SHA-256 hash of the data.
    """
    sha256 = hashlib.sha256()
    sha256.update(data.encode('utf-8'))
    return sha256.hexdigest()

# Public-private key encryption
def encrypt_data(data, public_key):
    """
    Encrypts the input data using the given public key.
    :param data: The data to be encrypted.
    :param public_key: The public key to be used for encryption.
    :return: The encrypted data.
    """
    return rsa.encrypt(data.encode('utf-8'), public_key)

def decrypt_data(data, private_key):
    """
    Decrypts the input data using the given private key.
    :param data: The data to be decrypted.
    :param private_key: The private key to be used for decryption.
    :return: The decrypted data.
    """
    return rsa.decrypt(data, private_key).decode('utf-8')

def main():
    # Generate a new public-private key pair
    (public_key, private_key) = rsa.newkeys(1024)

    # Input data
    data = input("Enter a message to encrypt: ")

    # Hash the data
    hashed_data = hash_data(data)

    # Encrypt the data
    encrypted_data = encrypt_data(hashed_data, public_key)

    # Decrypt the data
    decrypted_data = decrypt_data(encrypted_data, private_key)

    print(f"Original message: {data}")
    print(f"Hashed message: {hashed_data}")
    print(f"Encrypted message: {encrypted_data}")
    print(f"Decrypted message: {decrypted_data}")

if __name__ == '__main__':
    main()
