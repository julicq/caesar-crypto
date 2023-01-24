from hash_encryption import hash_data, encrypt_data
import rsa

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
    (public_key, private_key) = rsa.newkeys(2048)

    # Input data
    data = input("Enter a message to encrypt: ")
    hashed_data = hash_data(data)

    # Encrypt the data
    encrypted_data = encrypt_data(hashed_data, public_key)

    # Decrypt the data
    decrypted_data = decrypt_data(encrypted_data, private_key)

    # Compare the decrypted data to the original message
    if decrypted_data == hashed_data:
        print("Decryption successful!")
    else:
        print("Decryption failed.")

if __name__ == '__main__':
    main()
