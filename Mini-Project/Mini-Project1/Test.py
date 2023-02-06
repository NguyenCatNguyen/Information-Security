



#- The algorithm for encryption: EK(m) = m + K mod 26

#ciphertext += chr((ord(plaintext[i]) + ord(key[i % len(key)])) % 26 + 65)
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


# ciphertext += chr()