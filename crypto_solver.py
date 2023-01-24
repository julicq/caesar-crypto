from vigenere import caesar_decipher
from collections import Counter

def frequency_analysis(ciphertext):
    """
    Perform frequency analysis on a ciphertext to find the likely encryption key.
    :param ciphertext: The encrypted cryptogram.
    :return: The likely encryption key.
    """
    # Count the frequency of each letter in the ciphertext
    letter_count = Counter(ciphertext)
    # Sort the letters by frequency
    letter_count = dict(sorted(letter_count.items(), key=lambda x: x[1], reverse=True))

    # Compare the frequency of each letter to the letter frequency in the language used to write the original message
    english_letter_frequency = {'e': 12.02, 't': 9.10, 'a': 8.12, 'o': 7.68, 'i': 7.31, 'n': 6.95, 's': 6.28, 'r': 6.02, 'h': 5.92, 'd': 4.32, 'l': 3.98, 'u': 2.88, 'c': 2.71, 'm': 2.61, 'f': 2.30, 'y': 2.11, 'w': 2.09, 'g': 2.03, 'p': 1.82, 'b': 1.49, 'v': 1.11, 'k': 0.69, 'x': 0.17, 'q': 0.11, 'j': 0.10, 'z': 0.07}
    likely_key = None
    for letter, count in letter_count.items():
        for key, value in english_letter_frequency.items():
            if letter.lower() == key:
                likely_key = ord(letter.lower()) - ord(key)
                break
            if likely_key:
                break
            return likely_key


def get_likely_keyword(possible_plaintexts, common_words):
    """
    Given a list of possible plaintexts, find the likely keyword used to encrypt the ciphertext.
    :param possible_plaintexts: list of possible plaintexts
    :param common_words: list of common words
    :return: likely keyword
    """
    keyword_count = {}
    for plaintext in possible_plaintexts:
        words = plaintext.split()
        for word in words:
            if word in common_words:
                if word in keyword_count:
                    keyword_count[word] += 1
                else:
                    keyword_count[word] = 1
    if keyword_count:
        likely_keyword = max(keyword_count, key=keyword_count.get)
        return likely_keyword
    else:
        print("No common words found in any of the possible plaintexts. Please enter a different list of common words.")
        return None


def decrypt_keyword_caesar(ciphertext, common_words):
    """
    Decrypts a keyword-based caesar cipher cryptogram.

    :param ciphertext: The encrypted cryptogram.
    :param common_words: A list of common words that are likely to appear in the plaintext.
    :return: The decrypted plaintext message.
    """
    possible_plaintexts = []
    for keyword in common_words:
        plaintext = caesar_decipher(ciphertext, keyword)
        possible_plaintexts.append(plaintext)
    return possible_plaintexts

def get_likely_keyword(possible_plaintexts, common_words):
    """
    Given a list of possible plaintexts, find the likely keyword used to encrypt the ciphertext.
    :param possible_plaintexts: list of possible plaintexts
    :param common_words: list of common words
    :return: likely keyword
    """
    keyword_count = {}
    for plaintext in possible_plaintexts:
        words = plaintext.split()
        for word in words:
            if word in common_words:
                if word in keyword_count:
                    keyword_count[word] += 1
                else:
                    keyword_count[word] = 1
    likely_keyword = max(keyword_count, key=keyword_count.get)
    return likely_keyword

# def main():
#     ciphertext = input("Enter the encrypted cryptogram: ")
#     common_words = input("Enter a list of common words separated by commas: ").split(",")
#     possible_plaintexts = decrypt_keyword_caesar(ciphertext, common_words)
#     likely_keyword = get_likely_keyword(possible_plaintexts, common_words)
#     plaintext = vigenere.caesar_decipher(ciphertext, likely_keyword)
#     print(f"Likely keyword: {likely_keyword}")
#     print(f"Decrypted message: {plaintext}")

def main():
    ciphertext = input("Enter the encrypted cryptogram: ")
    likely_key = frequency_analysis(ciphertext)
    if likely_key is not None:
        plaintext = caesar_decipher(ciphertext, likely_key)
        print(f"Likely keyword: {likely_key}")
        print(f"Decrypted message: {plaintext}")
    else:
        print("Frequency analysis was not able to find the likely keyword. Please try a different method.")



if __name__ == '__main__':
    main()
