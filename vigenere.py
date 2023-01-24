def caesar_cipher(plaintext, keyword):
    """keyword_ascii
    Encrypts plaintext using a caesar cipher.

    :param plaintext: The plaintext message to be encrypted.
    :param keyword: The keyword to use as the shift value.
    :return: The encrypted ciphertext.
    """
    keyword = keyword.lower()
    keyword_ascii = [ord(c) - 97 for c in keyword]
    k = 0
    ciphertext = ""
    for char in plaintext:
        if char.isalpha():
            shift = keyword_ascii[k % len(keyword_ascii)]
            k += 1
            shift_char = chr((ord(char.lower()) + shift - 97) % 26 + 97)
            ciphertext += shift_char
        else:
            ciphertext += char
    return ciphertext

def caesar_decipher(ciphertext, keyword):
    """
    Decrypts ciphertext that was previously encrypted using a caesar cipher.

    :param ciphertext: The encrypted ciphertext to be decrypted.
    :param keyword: The keyword used as the shift value during encryption.
    :return: The decrypted plaintext message.
    """
    keyword = keyword.lower()
    keyword_ascii = [ord(c) - 97 for c in keyword]
    k = 0
    plaintext = ""
    for char in ciphertext:
        if char.isalpha():
            shift = keyword_ascii[k % len(keyword_ascii)]
            k += 1
            shift_char = chr((ord(char.lower()) - shift - 97) % 26 + 97)
            plaintext += shift_char
        else:
            plaintext += char
    return plaintext

def main():
    plaintext = input("Enter the message to encrypt/decrypt: ")
    keyword = input("Enter the keyword: ")
    choice = input("Enter 'e' to encrypt or 'd' to decrypt: ")

    if choice == 'e':
        ciphertext = caesar_cipher(plaintext, keyword)
        print(f"Encrypted message: {ciphertext}")
    elif choice == 'd':
        plaintext = caesar_decipher(plaintext, keyword)
        print(f"Decrypted message: {plaintext}")
    else:
        print("Invalid choice.")

if __name__ == '__main__':
    main()
