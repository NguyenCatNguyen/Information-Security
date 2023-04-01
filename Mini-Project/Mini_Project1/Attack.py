
#Task2
"""
Task 2: Next, you are expected to implement a brute force password cracker based on the Vigenere 
Cipher you just implemented. Your password cracker is expected to take three parameters: (1) a string 
of ciphertext; (2) an integer keyLength that denotes the length of the key; and (3) an integer 
firstWordLength that denotes the length of the first word of the plaintext. 
 
Your password cracker will test every possible key that has the length of keyLength: from all "A"s to all 
"Z"s. You cannot exploit the dictionary to guess the key, since the key may not be a valid word. 
 
For each key candidate, you will generate a "plaintext", and compare it with the dictionary (provided to 
you). In particular, you only need to check if the first word (number of letters of the word is given in 
firstWordLength) is a valid word in the dictionary. To do this, you need to load the dictionary into 
memory before processing any key, and search if the first word of the "plaintext" is in the dictionary. If 
Yes, display the plaintext and the key. However, do not stop, as the "plaintext" might be wrong. 
 
Efficiency is very important in evaluating each "plaintext" candidate. In some cases, a wrong key may 
generate a valid first word. Hence, you may get several "plaintexts" after all possible keys are tested. 
This is acceptable. You can look at the outputs and determine which key is correct.
"""
import itertools

# Decrypt ciphertext:
def decrypt(ciphertext, key):
    """
    Decrypt a ciphertext using a Vigenere cipher with a keyword.
    Add more implementation details here.
    """
    ciphertext = ciphertext.upper()
    plaintext = ""
    for i in range(len(ciphertext)):
        if ciphertext[i] == " ":
            plaintext += " "
        else:
            plaintext += chr((ord(ciphertext[i]) - ord(key[i % len(key)])) % 26 + 65)
    return plaintext


"""
1. Load the dictionary into memory as a set of words
2. Generate a list of all possible keys of length key_length consisting of the characters 'a' to 'z'
3. For each key in the list of keys:
  4. Decrypt the ciphertext using the key
  5. Get the first word of the decrypted text
  6. Check if the first word is in the dictionary
  7. If the first word is in the dictionary, display the decrypted text and the key
8. Repeat steps 3-7 for all keys in the list
"""

def E(filename, key):
    Dict = open(filename, "r")
    Output = open("Output.txt", "w")
    for line in Dict:
        encrypt = Vigeneres(line,key)
        Output.write("{encrypt}")
        Output.write("\n")

# Brute force password cracker:
def bruteForceCracker(ciphertext, keyLength, firstWordLength):
    # Load the dictionary into memory as a set of words
    dictionary = set()
    with open("MP1_dict.txt", "r") as f:
        for line in f:
            dictionary.add(line.strip())
    # Generate a list of all possible keys of length key_length consisting of the characters 'a' to 'z'
    keys = list(itertools.product("ABCDEFGHIJKLMNOPQRSTUVWXYZ", repeat=keyLength))
    # For each key in the list of keys:
    for key in keys:
        # Decrypt the ciphertext using the key
        plaintext = decrypt(ciphertext, key)
        # Get the first word of the decrypted text
        firstWord = plaintext[:firstWordLength]
        # Check if the first word is in the dictionary
        if firstWord in dictionary:
            # If the first word is in the dictionary, display the decrypted text and the key
            print(plaintext, key)

    

def Attack(ciphertext, keyLength, firstWordLength):
    # Posible keys
    keys = list(itertools.product("ABCDEFGHIJKLMNOPQRSTUVWXYZ", repeat=keyLength))
    # Open the dictionary file
    Dict = open("MP1_dict.txt", "r")
    # Correct plaintext
    plaintext = []
    # Using the Dict to decrypts the possible keys, then print the final result and key
    for line in Dict:
        for key in keys:
            if decrypt(ciphertext, key) == line:
                plaintext.append(line)
                print(line, key)
    print(plaintext)


            









Attack("MSOKKJCOSXOEEKDTOSLGFWCMCHSUSGX", 2, 6)












# Task 3
"""
Task 3: Use the brute force password cracker for the Vigenere Cipher you implemented in Task 2 to 
decrypt the following messages. 
 
1. "MSOKKJCOSXOEEKDTOSLGFWCMCHSUSGX" 
key length = 2; firstWordLength = 6 
 
2. "PSPDYLOAFSGFREQKKPOERNIYVSDZSUOVGXSRRIPWERDIPCFSDIQZIASEJVCGXAYBGYXFPSREKFMEX
EBIYDGFKREOWGXEQSXSKXGYRRRVMEKFFIPIWJSKFDJMBGCC" 
keyLength=3; firstWordLength = 7 
 
3. "MTZHZEOQKASVBDOWMWMKMNYIIHVWPEXJA" 
 
keyLength=4; firstWordLength = 10 
 
4. "SQLIMXEEKSXMDOSBITOTYVECRDXSCRURZYPOHRG" 
keyLength=5; firstWordLength = 11 
 
5. "LDWMEKPOPSWNOAVBIDHIPCEWAETYRVOAUPSINOVDIEDHCDSELHCCPVHRPOHZUSERSFS" 
keyLength=6; firstWordLength = 9 
 
6. "VVVLZWWPBWHZDKBTXLDCGOTGTGRWAQWZSDHEMXLBELUMO" 
keyLength=7; firstWordLength = 13

"""
