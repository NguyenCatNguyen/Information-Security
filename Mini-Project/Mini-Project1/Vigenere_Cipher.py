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



"""

# Task 1: Implement a simple Vigenere Cipher

def Vigeneres(plaintext, key):
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

def decryptVigenere(ciphertext, keyword):
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


def Encrypt(filename, key):
    # Access to the file
    Dict = open(filename, "r")
    # Loop through the file and read each line
    Output = open("Output.txt", "w")
    for line in Dict:
        encrypt = Vigeneres(line, key)
        Output.write(f"{encrypt}\n")
    Dict.close()

def Decrypt(filename, key):
    # Access to the file
    Dict = open(filename, "r")
    # Loop through the file and read each line
    Output = open("Result.txt", "w")
    for line in Dict:
        decrypt = decryptVigenere(line, key)
        Output.write(f"{decrypt}\n")
    Dict.close()


Encrypt("MP1_dict.txt", "CAT")
Decrypt("Output.txt", "CAT")



















def decryptVigenere(ciphertext, keyword):
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







"""
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