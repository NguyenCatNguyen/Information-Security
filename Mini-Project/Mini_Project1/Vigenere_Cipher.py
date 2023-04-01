"""
Name: Cat Nguyen
"""

"""
Task 1: Implement a simple Vigenere Cipher
- The algorithm for encryption: EK(m) = m + K mod 26
The algorithm for decryption: DK(m) = m - K mod 26
- Format:
■ The plaintext/ciphertext should only contain letters.
■ Assume valid input.
■ Spaces in the plaintext should be removed. 
■ Your input/output should be text strings, with both uppercase and lowercase letters. 
■ Not case sensitive. That is, both "A" and "a" must be converted to "1" (or "0") in your program.

- Vigenere Cipher is a polyalphabetic substitution cipher.
    - A polyalphabetic substitution cipher is a cipher that uses multiple substitution alphabets.
    - A polyalphabetic cipher is a cipher that uses multiple substitution alphabets.

Task 2: Implement a Password Cracker (brute forth)
- Three parameters: (1) a string of ciphertext; (2) an integer keyLength; and (3) an integer 
firstWordLength (i.e., the length of the first word of the plaintext).
= Requirements:
- Test every possible key that has the length of keyLength: from all "A"s to all "Z"s. 
    - You cannot exploit the dictionary to guess the key, since the key may not be a valid word.
- For each key candidate, generate a "plaintext", and compare it with the dictionary. 
    - Only need to check if the first word is a valid word in the dictionary. 
    - If Yes, display the plaintext and the key. However, do not stop, as the "plaintext" might be 
    wrong.
- Efficiency is very important in evaluating each "plaintext" candidate.


"""
import itertools
# Task 1: Implement a simple Vigenere Cipher

def Vigenere(plaintext, key):
    plaintext = plaintext.upper()
    key = key.upper()
    ciphertext = ""
    length = len(plaintext)
    for i in range(length):
        if plaintext[i] == " ":
            ciphertext += " "
        else:
            # The algorithm for encryption: EK(m) = m + K mod 26
            ciphertext += chr((ord(plaintext[i]) + ord(key[i % len(key)])) % 26 + 65)
    return ciphertext

def Decrypt(ciphertext, keyword):
    """
    Decrypt a ciphertext using a Vigenere cipher with a keyword.
    Add more implementation details here.
    """
    ciphertext = ciphertext.upper()
    keyword = keyword.upper()
    plaintext = ""
    for i in range(len(ciphertext)):
        if ciphertext[i] == " ":
            plaintext += " "
        else:
            plaintext += chr((ord(ciphertext[i]) - ord(keyword[i % len(keyword)])) % 26 + 65)
    return plaintext

def PasswordCraker(ciphertext, keyLength, firstWordLength):
    # 
    Dictionary = open("MP1_dict", "r")
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    keys = itertools.product(alphabet, repeat=keyLength)
    for key in keys:
        key = "".join(key)
        plaintext = Decrypt(ciphertext, key)
        first_word = plaintext[:firstWordLength]
        if first_word in Dictionary:
            print(f"Key: {key} | Plaintext: {plaintext}")



    







#s







"""
def BruteForce(string , key_length, first_word_length):
    string = string.upper()
    # The key is a combination of the letters in the alphabet
    # The key is a combination of the letters in the alphabet
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    # Create a list of all possible keys
    keys = itertools.product(alphabet, repeat=key_length)
    # Create a dictionary of valid words
    dictionary = set()
    with open("MP1_dict.txt", "r") as file:
        for line in file:
            dictionary.add(line.strip())
    # Loop through all possible keys
    for key in keys:
        # Convert the key from a tuple to a string
        key = "".join(key)
        # Decrypt the ciphertext
        plaintext = decrypt(string, key)
        # Check if the first word of the plaintext is a valid word
        first_word = plaintext[:first_word_length]
        if first_word in dictionary:
            print(f"Key: {key} | Plaintext: {plaintext}")


def brute_force_cracker(ciphertext, key_length, first_word_length, dictionary):
    # Load the dictionary into memory
    words = set(word.strip().lower() for word in open(dictionary))
    key_chars = [chr(i) for i in range(ord('a'), ord('z') + 1)]
    keys = itertools.product(key_chars, repeat=key_length)

    # Decrypt the ciphertext for each key and check if the first word is in the dictionary
    for key in keys:
        plaintext = ''
        for i in range(len(ciphertext)):
            char = ciphertext[i]
            char_index = ord(char.lower()) - ord('a')
            key_char = key[i % len(key)].lower()
            key_index = ord(key_char) - ord('a')
            plaintext += chr((char_index - key_index + 26) % 26 + ord('a'))

        first_word = plaintext[:first_word_length].lower()
        if first_word in words:
            print('Plaintext:', plaintext)
            print('Key:', key)


"MSOKKJCOSXOEEKDTOSLGFWCMCHSUSGX" 
key length = 2; firstWordLength = 6
    
#brute_force_cracker("MSOKKJCOSXOEEKDTOSLGFWCMCHSUSGX", 2, 6, "MP1_dict.txt")

#The output should be:
#Plaintext: thequickbrownfoxjumpsoverthelazydog
#Key: ('a', 'b')
#cipher = "MSOKKJCOSXOEEKDTOSLGFWCMCHSUSGX"

"""