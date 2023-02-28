## Introduction to Computer Security
### Security concepts



- `Caesar cipher`: is a type of substitution cipher in which each letter in the plaintext is replaced by a letter some fixed number of positions down the alphabet. For example, with a left shift of 3, D would be replaced by A, E would become B, and so on. The method is named after Julius Caesar, who used it in his private correspondence.

How many possible substitution alphabets? ■ 26! ≈ 4 * 1026
– Let’s try all permutations
■ Assume 109 tests per second, we have 10K nodes to run tests
■ How much time do we need?
■ 4 * 1013 seconds ~ 3 * 107 years
– How to reduce it?
- `Vigenere cipher`: is a method of encrypting alphabetic text by using a series of interwoven Caesar ciphers, based on the letters of a keyword. It employs a form of polyalphabetic substitution.



- `Cryptanalysisis` is the study of methods for obtaining the meaning of encrypted information `without accessing the secret information`.
- `Cryptology`: is the study of the mathematical principles behind the design and use of cryptographic systems.
    - Cryptographic + Cryptanalysis

- `Polyalphabetic`: is a method of encrypting alphabetic text by using multiple substitution alphabets. 
- `Vigenere cipher`: is a method of encrypting alphabetic text by using a series of interwoven Caesar ciphers, based on the letters of a keyword. It employs a form of polyalphabetic substitution.
    - Ek(m) = (m + k) mod 26
    - Dk(c) = (c – k) mod 26

- `OTP`: 
    - `Key`: the same key is used to encrypt and decrypt the message
    - `One-time`: the key is used only once
    - Problem: key must be as long as the message, insecure if the key is reused

- `Block cipher`: 