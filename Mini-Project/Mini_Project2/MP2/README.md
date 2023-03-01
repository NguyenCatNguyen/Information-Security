# Report Mini Project 2


## Task 1

### Part 1: Encrypt and Decrypt text.
#### cipher 1:

- Cipher text:
- `⪋朝εﳹ콘곳㻖淠䓻䶀襰#誔掎݋憾굋参禇᠐␰诱뛃ﾅ聬ㅣ᤭쀢⁸庂ꔍ㻵ꔙぃ艘∮袅決臫浺仍鵹춦熉턐니謶矵蔤蓖냁ꡧ⇌`

- Command use:
```
- Encrypt:
	openssl enc -aes-128-cbc -e -in plain.txt -out cipher1.txt -K 
	00112233445566778899aabbccddeeff -iv 01020304050607080910111213141516

- Decrypt:
	openssl enc -aes-128-cbc -d -in cipher1.txt -out plain1.txt -K
	00112233445566778899aabbccddeeff -iv 01020304050607080910111213141516
```
	
#### cipher 2
- `[�23��ʫ�f&[��}�d�ms��v�Ѝ�D�&���7�I4�ڼ)��� '�~*�����3@�I�V�_?,�we������aj%�Q��ze����M`

- Command use:
```
- Encrypt:
	openssl enc -aes-128-cfb -e -in plain.txt -out cipher2.txt -K 00112233445566778899aabbccddeeff 
	-iv 01020304050607080910111213141516

- Decrypt:
    openssl enc -aes-128-cfb -d -in cipher2.txt -out plain2.txt -K 00112233445566778899aabbccddeeff
	 -iv 01020304050607080910111213141516

```
#### cipher 3
```
- mD�`�K��c1(�c��?F�_L�t3/?��1f�E��l�KO7=@9�"&���SF��E����M�NL\��뺭�e47
\���{�ղ�\@�T/��=��>��n��ߵ�*�
```
- Command use:
```
- Encrypt: 
	- openssl enc -aes-128-ecb -e -in plain.txt -out cipher3.txt -K 00112233445566778899aabbccddeeff

- Decrypt:
	- openssl enc -aes-128-ecb -d -in cipher3.txt -out plain3.txt -K 00112233445566778899aabbccddeeff
```
### Part 2: Encrypt and Decrypt a picture file.
#### ECB:
- Code use:

![(ECB)[Task1/ECB_pic.png]](Task1/ECB_pic.png)

- Result:

![(ECB)[Task1/New_Enecb.png]](Task1/New_Enecb.png)

#### CBC:
- Code use:

![(CBC)[Task1/CBC_pic.png]](Task1/CBC_pic.png)

- Result:

![(CBC)[Task1/New_Encbc.png]](Task1/New_Encbc.png)



### Part 3: Answer questions.
- What do you see in Step 2? Please explain your observation.
	- In step 2, the encrypt using ECB mode still reveal the shape of the picture. On the other
	 hand, the encrypt using CBC mode is more difficult to see. From observation we can said that
	  CBC mode is more secure than ECB mode.

## Task 2	
### Part 1: Encrypt a file with ecb, cbc, cfb, and ofb.
#### Code use:
- openssl enc -aes-128-ecb -e -in Padding.txt -out Padecb.txt -k 00112233445566778899aabbccddeeff

- openssl enc -aes-128-cbc -e -in Padding.txt -out Padcbc.txt -k 00112233445566778899aabbccddeeff 
-iv 000102030405060708090a0b0c0d0e0f

- openssl enc -aes-128-cfb -e -in Padding.txt -out Padcfb.txt -k 00112233445566778899aabbccddeeff 
-iv 000102030405060708090a0b0c0d0e0f

- openssl enc -aes-128-ofb -e -in Padding.txt -out Padofb.txt -k 00112233445566778899aabbccddeeff

#### Question:
- Which modes need padding?
	- ECB, CBC, CFB, OFB need padding.
- Some modes require padding, explain why
	- ECB, CBC, CFB, OFB need padding because based on the size of output data, the size of input 
	data must be a multiple of the block size. If the size of the input data is not a multiple of 
	the block size, then the data must be padded to the next multiple of the block size.

### 2 Encrypt using cbc and report the size of the file.
#### File 1

- Encrypt
- openssl enc -aes-128-cbc -e -in file1.txt -out file1E.txt -k 00112233445566778899aabbccddeeff 
-iv 000102030405060708090a0b0c0d0e0f

-Decrypt
- openssl enc -aes-128-cbc -d -in file1E.txt -out file1D.txt -k 00112233445566778899aabbccddeeff
 -iv 000102030405060708090a0b0c0d0e0f 

#### File 2
- Encrypt
- openssl enc -aes-128-cbc -e -in file2.txt -out file2E.txt -k 00112233445566778899aabbccddeeff 
-iv 000102030405060708090a0b0c0d0e0f

-Decrypt
- openssl enc -aes-128-cbc -d -in file2E.txt -out file2D.txt -k 00112233445566778899aabbccddeeff 
-iv 000102030405060708090a0b0c0d0e0f 
#### File 3
- Encrypt
- openssl enc -aes-128-cbc -e -in file3.txt -out file3E.txt -k 00112233445566778899aabbccddeeff 
-iv 000102030405060708090a0b0c0d0e0f

-Decrypt
- openssl enc -aes-128-cbc -d -in file3E.txt -out file3D.txt -k 00112233445566778899aabbccddeeff 
-iv 000102030405060708090a0b0c0d0e0f 
#### Size of files

- File1 = 32
- File2 = 32
- File3 = 48



### 3 Decrypt the files and 
#### File 1
- openssl enc -aes-128-cbc -d -in file1E.txt -out file1DP.txt -k 00112233445566778899aabbccddeeff 
-iv 000102030405060708090a0b0c0d0e0f -nopad
#### File 2
- openssl enc -aes-128-cbc -d -in file2E.txt -out file2DP.txt -k 00112233445566778899aabbccddeeff 
-iv 000102030405060708090a0b0c0d0e0f -nopad

#### File 3
- openssl enc -aes-128-cbc -d -in file3E.txt -out file3DP.txt -k 00112233445566778899aabbccddeeff 
-iv 000102030405060708090a0b0c0d0e0f -nopad

#### Report
- If we decrypt like regularly the size of the file after decrypt would be the same as the original size of the file.
- 


## Task 3
- Command use to create text file:
```
yes "this is a text file" | head -c 1KB > f2.txt
```
#### ECB:
```
- Encrypt: 
- openssl enc -aes-128-ecb -e -in f2.txt -out f2ECB.txt -k 00112233445566778899aabbccddeeff
- Decrypt:
- openssl enc -aes-128-ecb -d -in f2ECB.txt -out f2ECB_d.txt -k 00112233445566778899aabbccddeeff
```

- Picture before corrupt

	![(ECB)[Task3/ECB_Before.png]](Task3/ECB_Before.png)
- Picture after corrupt

	![(ECB)[Task3/ECB_After.png]](Task3/ECB_After.png)
- Corrupt text:

	![(ECB)[Task3/ECB_Corrupt.png]](Task3/ECB_Corrupt.png)


#### CBC: 
```
- Encrypt:
- openssl enc -aes-128-cbc -e -in f2.txt -out f2CBC.txt -k 00112233445566778899aabbccddeeff
 -iv 000102030405060708090a0b0c0d0e0f
- Decrypt:
- openssl enc -aes-128-cbc -d -in f2CBC.txt -out f2CBC_d.txt -k 00112233445566778899aabbccddeeff 
-iv 000102030405060708090a0b0c0d0e0f
```	
- Picture before corrupt

	![(CBC)[Task3/CBC_Before.png]](Task3/CBC_Before.png)
- Picture after corrupt:

	![(CBC)[Task3/CBC_After.png]](Task3/CBC_After.png)
- Corrupt text:

	![(CBC)[Task3/CBC_Corrupt.png]](Task3/CBC_Corrupt.png)
#### CFB: 
```
- Encrypt:
- openssl enc -aes-128-cfb -e -in f2.txt -out f2CFB.txt -k 00112233445566778899aabbccddeeff 
-iv 000102030405060708090a0b0c0d0e0f
- Decrypt:
- openssl enc -aes-128-cfb -d -in f2CFB.txt -out f2CFB_d.txt -k 00112233445566778899aabbccddeeff 
-iv 000102030405060708090a0b0c0d0e0f
```
- Picture before corrupt

	![(CFB)[Task3/CFB_Before.png]](Task3/CFB_Before.png)
- Picture after corrupt

	![(CFB)[Task3/CFB_After.png]](Task3/CFB_After.png)
- Corrupt text:

	![(CFB)[Task3/CFB_Corrupt.png]](Task3/CFB_Corrupt.png)	

#### OFB:
```
- Encrypt:
- openssl enc -aes-128-ofb -e -in f2.txt -out f2OFB.txt -k 00112233445566778899aabbccddeeff
- Decrypt:
- openssl enc -aes-128-ofb -d -in f2OFB.txt -out f2OFB_d.txt -k 00112233445566778899aabbccddeeff
```
- Picture before corrupt

	![(OFB)[Task3/OFB_Before.png]](Task3/OFB_Before.png)

- Picture after Corrupt

	![(OFB)[Task3/OFB_After.png]](Task3/OFB_After.png)

- Corrupt text:

	![(OFB)[Task3/OFB_Corrupt.png]](Task3/OFB_Corrupt.png)


#### Report
1. ECB
- ECB encrypt each block independently. So when the file got corrupt, only one particular block got 
corrupt. The rest of the file is decrypt correct the same as the original file
2. CBC
- CBC encrypt each block depend on the previous block. So when the file got corrupt, the block that got 
corrupt will affect the next block. The rest of the file is decrypt correct the same as the original file
3. CFB
- CFB encrypt each block depend on the previous block. So when the file got corrupt, the block that got 
corrupt will affect the next block. The rest of the file is decrypt correct the same as the original file
4. OFB
- Only a letter in line 4 got affect because of the corrupt in the file. The rest of the file is the same 
as the original file. The decryption output produce `txft` instead of text. So we can said that when OFB 
file being corrupt, the decryption will still produce the correct output except the block that got corrupt.

- Based on your observations, what is the difference in error propagation among
different encryption modes?
	- ECB: the text still being produce but their are extra cipher text at the block that got corrupt.
	- CBC: the text still being produce but their are extra cipher text at the block that got corrupt and 
	there the block right after the block that got corrupt got corrupt too.
	- CFB: the text that got corrupt is unreadable, the block before and after the text also got corrupt. 
	Everything else is the same as the original file.
	- OFB: only a single letter got corrupt.

## Task 4

### Part1 using different and the same iv for test
- Same:
	- Using the same iv result in the same ciphertext because the same iv will produce the same keystream. 
	So the same keystream will be XOR with the plaintext to produce the same ciphertext.
- Different:
	- Using different iv result in different ciphertext because iv influences the ecryption of the first 
	block. So the first block will be different and also affect the rest of the block.
- So using different iv is more secure than using the same iv since if we using the same iv, the attacker 
can easily analyze the ciphertext and find the pattern of the keystream. So the attacker can easily decrypt 
the ciphertext. Using different iv will help prevent this attack.

### Part2 find the unknow plaintext
#### Question 4. 
```
Based on your result, is aes-128-ofb secure when the same IV is used? If aes-128-cfb
is used, how much of P2 can be revealed?
```
	- Based on the result we can see that the aes-128-ofb is not secure when the same IV is used. The attacker
	can easily decrypt the ciphertext and get the plaintext. 
	- If aes-128-cfb is used, 

- The decrypt answer for P2 is `This is a secret message`










































