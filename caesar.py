def main():
    plaintext = input("Enter the message to encrypt/decrypt: ")
    shift = int(input("Enter the shift value: "))
    choice = input("Enter 'e' to encrypt or 'd' to decrypt: ")

    if choice == 'e':
        ciphertext = caesar_cipher(plaintext, shift)
        print(f"Encrypted message: {ciphertext}")
    elif choice == 'd':
        plaintext = caesar_decipher(plaintext, shift)
        print(f"Decrypted message: {plaintext}")
    else:
        print("Invalid choice.")

def caesar_cipher(plaintext, shift):
    """
    Encrypts plaintext using a Caesar cipher.
    
    :param plaintext: The plaintext message to be encrypted.
    :param shift: The number of positions to shift the alphabet.
    :return: The encrypted ciphertext.
    """
    ciphertext = ""
    for char in plaintext:
        if char.isalpha():
            shift_char = chr((ord(char) + shift - 97) % 26 + 97)
            ciphertext += shift_char
        else:
            ciphertext += char
    return ciphertext


def caesar_decipher(ciphertext, shift):
    """
    Decrypts ciphertext that was previously encrypted using a Caesar cipher.

    :param ciphertext: The encrypted ciphertext to be decrypted.
    :param shift: The number of positions the alphabet was shifted during encryption.
    :return: The decrypted plaintext message.
    """
    plaintext = ""
    for char in ciphertext:
        if char.isalpha():
            shift_char = chr((ord(char) - shift - 97) % 26 + 97)
            plaintext += shift_char
        else:
            plaintext += char
    return plaintext


if __name__ == "__main__":
    main()