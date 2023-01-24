from vigenere import caesar_decipher

def brute_force_decrypt(ciphertext, common_words):
    """
    Attempts to decrypt a keyword-based Caesar Cipher cryptogram by trying all possible keywords.
    :param ciphertext: The encrypted cryptogram.
    :param common_words: A list of common words that are likely to be used as the encryption keyword.
    :return: The decrypted plaintext message, if successful.
    """
    for keyword in common_words:
        plaintext = caesar_decipher(ciphertext, keyword)
        print(f"Keyword: {keyword}")
        print(f"Plaintext: {plaintext}")

def main():
    ciphertext = input("Enter the encrypted cryptogram: ")
    common_words = input("Enter a list of common words separated by commas: ").split(",")
    brute_force_decrypt(ciphertext, common_words)

if __name__ == '__main__':
    main()
