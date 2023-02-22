 # Homework 1  
 - Name: Cat Nguyen
 - ID: 3077463

## Classic ciphers.

### Problem 1:
- A substitution cipher replaces each letter with the one at the i-slots to its right. Please use the key "DAWN" to 
decrypt the ciphertext "vealruwgwwk". Show your decryption process briefly. Assume the letter "A" is mapped to 
position "0". A detailed mapping is provided as follows.

| Position | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 
|----------|---|---|---|---|---|---|---|---|---|---|----|----|----|
| Letter   | A | B | C | D | E | F | G | H | I | J | K  | L  | M  |
| Position | 13| 14| 15| 16| 17| 18| 19| 20| 21| 22| 23 | 24 | 25 |
| Letter   | N | O | P | Q | R | S | T | U | V | W | X  | Y  | Z  |




#### Answer:

| Cipher | V | E | A | L | R | U | W | G | W | W | K | 
|--------|---|---|---|---|---|---|---|---|---|---|---| 
| Position| 21| 4 | 0 | 11| 17| 20| 22| 6 | 22| 22| 10|
| Key Positon | 3 | 0 | 22| 13| 3 | 0 | 22| 13| 3 | 0 | 22| 
| New Position | 18| 4 | 4 | 24| 14| 20| 0 | 19| 19| 22| 12|
| Plain  | S | E | E | Y | O | U | A | T | T | W | O |

- The final answer is `seeyouattwo`

- STEP BY STEP:
    - Using the key "DAWN", we have the location of the first letter of the key is 3, 0, 22, 13.
    - Then we find the position of the ciphertext in the table above.
    - Then we replace the position of the ciphertext with the new position by using the key.
    - Since we can is decrypt the text from ciphertext so it move from right to left.



### Problem 2:
```
- What is polyalphabetic substitution cipher? Compared with shift cipher, discuss two major differences between the two ciphers.
```

- `Polyalphabetic substitution cipher`: is a type of substitution cipher that use multiple alphabets to 
- `Shift cipher`: is a monoalphabetic substitution cipher in which each letter in the plaintext is replaced by a letter some fixed number of positions down the alphabet.
- The main different between the two are:
    - `Polyalphabetic substitution cipher` use multiple alphabets to encrypt the plaintext.
    - `Shift cipher` use only one alphabet to encrypt the plaintext.






### Problem 3:
- One-time pad is used to encrypt messages. If an attacker obtains the ciphertext and the corresponding plaintext message, can 
he find the encryption key? Does this mean OTP is vulnerable to the known-plaintext attacks?


### Problem 4:
- What is frequency analysis? Please use frequency analysis to crack the below ciphertext. You can 
use tool to help compute the statistics, https://www.ittc.ku.edu/~fli/565/frequency_analysis.html. 
o kewixn zol yg yomn wnokvpn gt o sgvfypl ek yg xggm oy bgz wofl zofy ef ofq bgz wofl zofy 
gvy ygfl jxoep 
Hint: O=A, G=O, X=L, W=M, Y=T 
- `Frequency analysis`: is a method of analyzing the frequency of each letter in a ciphertext to find the key.


## Secret-key cryptography.

### Problem 5:
-  What is the block size and key length in DES encryption? Can two different keys encrypt the same 
plaintext into the same ciphertext? Why or why not? 
 
### Problem 6:
-  What is the meet-in-the-middle attack? Please briefly explain why double-DES is vulnerable to this 
attack, but triple-DES is not. 
 


### Problem 7:
-  What is the key exhaustive attack? If an attacker uses this attack to break a ciphertext encrypted by 
AES-192-CBC. Assume he uses a computer with 4GHz CPU to crack the keys and it takes about 100 
cycles to test one key. How much time on average does he need to find the correct encryption key? 
 

### Problem 8:
-  Errors in one block will propagate to other blocks when the CBC mode is used in block ciphers.  
a.  Suppose an error occurs during transmission. One bit of the first ciphertext block is wrong. 
When the receiver tries to recover the message, how many plaintext blocks cannot be 
decrypted correctly? 
b.  Suppose a one-bit error occurs in the first block of the plaintext message. After encrypting 
the message, how many ciphertext blocks will have error bits? When the receiver recovers 
the message, how many plaintext blocks cannot be decrypted correctly? 
 
## Public-key cryptography 
### Problem 9
-  Use RSA to encrypt the message “EECS”. Assume p = 3 and q=11, and e=7. Please show the 
encryption steps (assume A=1). What is the security problem with textbook RSA encryption?  
 
### Problem 10
- The Diffie-Hellman key negotiation protocol is vulnerable to the man-in-the-middle attack.  Please 
explain the attack process and the mitigation methods. 
 
### Problem 11
- SHA-256 is commonly used as the signing algorithm on SSL certificates. Which hash properties are 
desired in this use case? To successfully generate a collision (i.e., two certificates with the same 
signature), how many attempt on average should the attacker try (assume the desired collision 
probability is greater than 50%)? 
 

### Problem 12
- What is HMAC? Find one use case of HMAC in real-world applications. Which hash 
property/properties is utilized by this application? 
