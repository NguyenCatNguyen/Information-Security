# Exam 2 Review
## Authentication 
### I.Basic concepts
- Why `authenticate`? How?
    - Authenticate is the process of verifying the identity of a user or system. 
    - `Goal of authentication`: bind identity to card/token/password/key
    - By using a secret key, the AS can verify the identity of Alice
- `Certificates` is a token containing:
    `PIC1`
### II.Public-Key Infrastructure (PKI)
- PKI: bind  identity to public key
    - Crucial as people will use key to communicate with principal whose identity is bound to key
    - Erroneous binding means no secrecy between principlas
    - Assume principal identified  by an acceptable name - called Common Name
- A PKI consists of: Cetificates, Certificates Authority (CA), a resposity for retrieving certificates, A method of evaluating a chain of certificates from known public keys to the tartget name, amethod of revoking certificates
- PKI Trust Models
    - Hierarchical CAs with cross-certification
        - Multiple root CAs that are cross-certified
    - Oligarchy model (commonly used in browsers)
        - Browsers or Operating Systems come pre-configured with multiple trust anchor certificates
        - New certificates can be added( be careful)
        - Bad certificate can be revoked
    - Distributed model
        - No root CA; instead, users certify each other to build a "web of trust"
- PKI Security
    - What happen if root authority is compromised?
        - The certificate chain rooted from this CA is corrupted
    - PKI faces many challenges
        - Hash collisions: Obsolete hash algorithms
        - Weak security at CAs: attackes can issue rogue certificates
        - Users not aware of attacks happening
### III.Certificate
- Certificate Authority (CA)
    - CA is a trusted third party who issues certificates
- CA hierarchy `PIC2`
- Certificate Verification `PIC3`
- Certificate Expiration
    - Certificate holds an expiration date and time
    - Certificate may need to be **revoked** before expiration
    - Revocation is **very important** to PKI
- Revocation `PIC4`
    - Certificate revocation list (CRL)
        - A list of revoked certificates
        - Issued by CA
        - Signed by CA
        - Distributed to clients
        - Clients check CRL before using certificate
    - Online Certificate Status Protocol (OCSP)
        - A protocol for checking the status of a certificate
        - Issued by CA
        - Signed by CA
        - Distributed to clients
        - Clients check OCSP before using certificate
- Rogue Certificate `PIC5`
### IV.Password authentication
- Authentication is the process of verifying the identity of a user or system.
- How do you prove to someone that you are who u claim to be?
    - Show **credential**
- Credential can be
    - Something you know (password, certificate,..)
    - Something you have (token, IP address, hardware/moblie device,..)
    - Something you are (biometric)
- How to steal or exploit passwords?
    - After a sucessful intrusion
    - `Steal` install sniffer or keylogger to steal passwords
    - `Exploit` fetch password files and run cracking tools
- Use of strong password, why?
    - Because weak password caused 30% of ransomware infections
    - Stolen credentials led to nearly 50% of attacks
- How to **store** password in the system? 
    - In password files indexed by user ID, in plaintext, Encrypted, hashed.
    - Hashing, Salting, Encryption, Password managers

#### a.Password Hashing
- `Hashing` is the process of converting a password into a unique string of characters that cannot be reversed.
- When user enters a password
    - System computer H(password) and compares with the entry in the password file
    - System does not store the actual password
- Password hash funtion
    - `Onewayness`: given H(password), it is hard to deduce password
    - `slow to compute`: restrict the speed of brute force attacks

#### b.The way to crack password
- `Brute force attack`: after attacker gets ur password file, he tries to hash all possible values and compare the results witht e entries in the password file. 
    - There are 94 candidate characters, 8 characters long password, 94^8 = 6.5*10^14 possible passwords
    - But since password are not truly randomm. **Dictionary attack** is more effective
- `Dictionary attack`: attacker uses a dictionary of common passwords to crack the password
    - Attacker pre-computes H(password) for every word in the dictionary.
    - Pre-computing needs to be done only once and offine
    - One the password file is obtaioned, cracking is done immediately(search and compare)
    - Password guessing tools also ultilize frequency of letters, password patterns, etc.
- `Rainbow table attack`: attacker pre-computes H(password) for all possible passwords and stores the results in a table
    - A space-time tradeoff, can purchase from the Internet

#### c.Countermeasures: 
- `Salting` is the process of adding a random string to the password before hashing
    - is a random value chosen for each user
        - It chosen randomly when password is first set and stored in the password file
- password hash = H(salt + password)
- Users with the same password have different entries in the password file
- Salting adds randomness to password hash, make offline dictionary attack harder
- **Advantages** of Salting
    - Without salting, attacker can pre-compute hashes of all dictionary words once.
        - for **ALL** password entries
        - for all hash algorithms (the same hash function is used on all UNIX machines)
        - Hash of identical passwords have identical value (one table can be used for all password files)
    - With salting, attacker must pre-compute hashes of all dictionary words once
        - for **EACH** password entry (with 12 bit salt, same password can have 2^12 = 4096 different hashes)
        - for all hash algorithms, attacker must try all dictionary words for each salt value in the password file
#### d.Other Password Security Risks
- Weak password, default password, keystroke loggers, broken implementations, social engineering,
- Password strength
- Usability -- password manager can help
    - Hard to remember passwords
    - Password management issues
        - Password reuse
        - Password sharing
        - Heavy reuse
#### e.Way to improve password security
- `Password managers` are software programs that store and manage passwords
    - What happen when password manager is compromised?
        - Password manager is a single point of failure
        - Password manager can be compromised by malware
        - Password manager can be compromised by social engineering
        - Password manager can be compromised by brute force attack
        - Password manager can be compromised by insider attack
- `Graphical passwords` easy to remember, no need to write down
    - Draw a picture, select a point, select a color
    - Side channel attack may reveal the password
- Add `biometrics`: unique, hard to fake, no need to remember
    - Fingerprint, retina, voice, face, etc.
    - Require special hardware, hard to revoke, false positive, can be stolen
- `Multi-factor authentication`
    - Levarage **more than one** authentication mechanism  for authentication
    -  Google: Password + SMS
    - FIDO: Password + hardware
###  Distributed authentication
#### a. Threads
- `User Impersonation: a malicious 








    - Basic concepts
    - Kerberos
    - SAML
    - OAuth
### Kerberos
Kerberos system
What is the responsibility of each server
    - Scenario,design goals
    - Architecture
    - The protocol, ticket, session key, authenticator
    - Short-term credentials
    -Kerberos Single Sign-On (SSO)

## DS Security
- Basic concepts
    - CIA
- Inference attacks
    - Tracker attack
    - Possible controls
- Access control
    - Policy vs enforcement mechanism
    - Access control models: DAC, RBAC
    - DAC: subjects and privileges, GRANT/REVOKE
    - RBAC

## OS Security
- OS must protect users from each other - seperation
    - Memory protection: protecting OS kernel, process isolation
    - File protection: access control 
    - General control and access to objects: refrence monitor and access control.
    - User authentication
- Access control (general objects)
    - Trojan horse

## Software Security
- Software flaws(non-malicious)
    -Buffer overflow: what causes the problem, how to mitigate
    - Incomplete mediation: injection attacks, why they work
    - TOCTTOU: what is the vulnerability
    
What is the cost of the problem how to solve it
Injection attactk
Different type of injection attack
Risk condition: time of change


# Authentication

## Public-Key Infrastructure(PKI)

Goal of authentication: bind identity to card/token/password/key
- Public key infrastructure: bind identity to public key
– Crucial as people will use key to communicate with principal whose identity is bound to key
– Erroneous binding means no secrecy between principals
– Assume principal identified by an acceptable name – called Common Name

## A PKI consists of:
Certificates
Certificates Authority(CA)
What is a trust
Password authentication:
What is sources? Why we use sources
Kerberos system
What is the responsibility of each server
What is
Dfbdj
II. OS Security

III. Software Security

What is the cost of the problem how to solve it
Injection attactk
Different type of injection attack
Risk condition: time of change
Software Security

Stack Overflow
Dj