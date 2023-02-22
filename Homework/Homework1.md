 # Homework 1  
 - Name: Cat Nguyen
 - ID: 3077463

## Classic ciphers.

### Problem 1:
``` 
A substitution cipher replaces each letter with the one at the i-slots to its right. Please use the key "DAWN" to 
decrypt the ciphertext "vealruwgwwk". Show your decryption process briefly. Assume the letter "A" is mapped to 
position "0". A detailed mapping is provided as follows.
```
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

- The final answer is `see you at two`

- STEP BY STEP:
    - Using the key "DAWN", we have the location of the first letter of the key is 3, 0, 22, 13.
    - Then we find the position of the ciphertext in the table above.
    - Then we replace the position of the ciphertext with the new position by using the key.
    - Use the key to find the new position of the ciphertext.
    - Then we find the plaintext by using the new position of the ciphertext.


### Problem 2:
```
- What is polyalphabetic substitution cipher? Compared with shift cipher, discuss two major differences between the two ciphers.
```

- `Polyalphabetic substitution cipher`: is a type of substitution cipher that use multiple alphabets to encrypt the plaintext.
- `Shift cipher`: is a monoalphabetic substitution cipher in which each letter in the plaintext is replaced by a letter some fixed 
number of positions down the alphabet.
- The main different between the two are:
    - `Polyalphabetic substitution cipher` use **multiple** alphabets to encrypt the plaintext.
    - `Shift cipher` use only **one** alphabet to encrypt the plaintext.


### Problem 3:
```
- One-time pad is used to encrypt messages. If an attacker obtains the ciphertext and the corresponding plaintext message, can 
he find the encryption key? Does this mean OTP is vulnerable to the known-plaintext attacks?
```
- No, the attacker cannot directly find the encryption key, but he can find the key by using the `XOR` operation. And the 
attacker can change the plaintext to something else by using the key.
- Yes, OTP is vulnerable to KPA if the attacker has access to enough ciphertext and plaintext pairs. And using the `XOR` operation, 
the attacker can use `XOR` operation to find to cancel the key out and obtain the need information. Which can help reveal information 
about the key. 
### Problem 4:
```
- What is frequency analysis? Please use frequency analysis to crack the below ciphertext. You can 
use tool to help compute the statistics, https://www.ittc.ku.edu/~fli/565/frequency_analysis.html. 
o kewixn zol yg yomn wnokvpn gt o sgvfypl ek yg xggm oy bgz wofl zofy ef ofq bgz wofl zofy 
gvy ygfl jxoep 
Hint: O=A, G=O, X=L, W=M, Y=T 
```
- `Frequency analysis`: is a method of analyzing the frequency of each letter in a ciphertext to find the key.
- The final answer is `a simple way to take measure of a country is to look at how many want in and how many want out tony blair`


## Secret-key cryptography.

### Problem 5:
```
-  What is the block size and key length in DES encryption? Can two different keys encrypt the 
same plaintext into the same ciphertext? Why or why not? 
```
- DES: 
    - Block size: 64 bits
    - Key length: 56 bits
- No, two different keys cannot encrypt the same plaintext into the same ciphertext. Because the key 
is used to encrypt the plaintext. If the key is different, the ciphertext will be different.

 
### Problem 6:
```
-  What is the meet-in-the-middle attack? Please briefly explain why double-DES is vulnerable 
to this attack, but triple-DES is not. 
 ```
 - `Meet-in-the-middle attack`: is an attack that targets encryption algorithms that use a symmetric 
 key. The attacker can find the key by using the `XOR` operation.
 - Double-DES is vulnerable to this attack because the size of its key space is relatively small. And 
 the attacker can use the `XOR` operation to find the key.
 - Triple-DES is not vulnerable to this attack because the size of its key space is relatively large.
  And the attacker cannot use the `XOR` operation to find the key. It also design to be resistant to 
  various attacks on DES, including the meet-in-the-middle attack.


### Problem 7:
```
-  What is the key exhaustive attack? If an attacker uses this attack to break a ciphertext encrypted by 
AES-192-CBC. Assume he uses a computer with 4GHz CPU to crack the keys and it takes about 100 
cycles to test one key. How much time on average does he need to find the correct encryption key? 
```
- `Key exhaustive attack`: is an attack that tries all possible keys to find the correct key.
- Answer:
    - The total number of keys is $2^{192}$.
    - The time to test one key is 100 cycles.
    - The CPU speed is 4GHz.

    $$(2^{192}*100)/(4*10^{9}) = 1.57*10^{50}$$

- So it take about $1.57*10^{50}$ seconds to find the correct encryption key.
- That equivalent to $4.9*10^{42}$ years.

 

### Problem 8:
```
-  Errors in one block will propagate to other blocks when the CBC mode is used in block ciphers.  
a.  Suppose an error occurs during transmission. One bit of the first ciphertext block is wrong. 
When the receiver tries to recover the message, how many plaintext blocks cannot be 
decrypted correctly? 
b.  Suppose a one-bit error occurs in the first block of the plaintext message. After encrypting 
the message, how many ciphertext blocks will have error bits? When the receiver recovers 
the message, how many plaintext blocks cannot be decrypted correctly? 
 ```
- a. When the receiver tries to recover the message, the first plaintext block cannot be decrypted correctly. And this error will follow to the next block and so on. The first plaintext block may still be decrypted correctly if the error in the first ciphertext block does not affect the initialization vector used in the decryption process. But the second plaintext block cannot be decrypted correctly. So the answer is 1.
- b. All subsequent ciphertext blocks will have error bits. And when the receiver recovers the message, the first plaintext block cannot be decrypted correctly. And this error will follow to the next block and so on. The first plaintext block may still be decrypted correctly if the error in the first ciphertext block does not affect the initialization vector used in the decryption process. But the second plaintext block cannot be decrypted correctly. So the answer is 1.
## Public-key cryptography 
### Problem 9
```
-  Use RSA to encrypt the message “EECS”. Assume p = 3 and q=11, and e=7. Please show the 
encryption steps (assume A=1). What is the security problem with textbook RSA encryption? 
```
- First, find the public key and private key. 
    - Calculate n = p*q = 3*11 = 33
    - Calculate $\phi(n)$ = $\phi(33)$ = 20
    - Calculate d = e^{-1} mod $\phi(n)$ = 3
    - From the above calculation, we can get the public key and private key.
        - Public key: (e, n) = (7, 33)
        - Private key: (d, n) = (3, 33)
- Second,Convert the message to numetric type: `EECS` = {5,5,3,19}
- Third, encrypt the message:
    - $c = m^e mod n$
    - $c = 5^7 mod 33 = 14$
    - $c = 5^7 mod 33 = 14$
    - $c = 3^7 mod 33 = 9$
    - $c = 19^7 mod 33 = 13$
- So the ciphertext is: {14, 14, 9, 13}

 
### Problem 10
```
- The Diffie-Hellman key negotiation protocol is vulnerable to the man-in-the-middle attack.  Please 
explain the attack process and the mitigation methods. 
```
#### Attack process:
- 1. Eve intercepts the communication between Alice and Bob.
- 2. Eve modifies the message sent by Alice to Bob.
- 3. Eve sends the modified message to Bob.
- 4. Bob receives the modified message and calculates the shared secret key.
- 5. Eve receives the shared secret key from Bob.
- 6. Eve can use the shared secret key to decrypt the message sent by Alice to Bob.
- 7. Eve uses the shared secret key to encrypt the message sent by Bob to Alice.
- 8. Eve sends the encrypted message to Alice.
- 9. Alice receives the encrypted message and calculates the shared secret key.

- So by intercepting the communication between Alice and Bob, Eve can decrypt the message sent by Alice to Bob and encrypt the message sent by Bob to Alice. Eve can also calculate the shared secret key between Alice and Bob.
#### Mitigation methods:
- 1. Use published DH numbers. Using a common base, select `permanent` public and private numbers, and publish public numbers via some trusted channels.
- 2. Authenticated DH exchange. Authenticate the communicating parties and verify the message in not modified. This requires sharing some kind of secret between Alice and Bob. 




 
### Problem 11
```
- SHA-256 is commonly used as the signing algorithm on SSL certificates. Which hash properties are 
desired in this use case? To successfully generate a collision (i.e., two certificates with the same 
signature), how many attempt on average should the attacker try (assume the desired collision 
probability is greater than 50%)? 
```
- The hash properties that are desired in this use case are:
    - Pre-image resistance
    - Second pre-image resistance
    - Collision resistance
- To successfully generate a collision, the attacker should try $2^{128}$ hash computations on average to find a collision with a probability greater than 50%.

 

### Problem 12
```
- What is HMAC? Find one use case of HMAC in real-world applications. Which hash 
property/properties is utilized by this application? 
```
- HMAC - Hash-based Message Authentication Code is a mechanism for calculating a message authentication code (MAC) involving a cryptographic hash function in combination with a secret cryptographic key.
- A use case of HMAC in real-world applications is the authentication of API requests in web applications. 
    - The hash property that is utilized by this application is collision resistance.

