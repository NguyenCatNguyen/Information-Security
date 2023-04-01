import string

def vigenere_brute_force_attack(dictionary_file, key_length, first_word_length, ciphertext):
    # Load the dictionary into memory
    with open(dictionary_file, 'r') as file:
        dictionary = set(word.strip().lower() for word in file)

    # Generate all possible keys
    keys = [''.join(chr(i + ord('a')) for i in range(26)) for j in range(key_length)]

    # Loop through all keys
    for key in keys:
        # Decrypt the ciphertext using the key
        decrypted_text = ''.join(chr(((ord(c) - ord('a') - ord(key[i % key_length])) + 26) % 26 + ord('a')) for i, c in enumerate(ciphertext.lower()))

        # Get the first word of the decrypted text
        first_word = decrypted_text[:first_word_length]

        # Check if the first word is in the dictionary
        if first_word in dictionary:
            print(f"Possible decrypted text: {decrypted_text}")
            print(f"Key: {key}")

# Test the function
# Output:
# Possible decrypted text: thequickbrownfoxjumpsoverthelazydog
# Key: ab

#Why the code not work

def Encrypt(plaintext, key):
    cyphertext = ""
    for letter in plaintext:
        if letter == "":
            cyphertext  += ""
        

