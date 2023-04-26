

- Coverage: Lecture 19 to Lecture 22
- Network security (about 60%)
- Firewall and IDS (about 40%)
- Web security (20%)


# Network Security
## Network Vulnerabilities
### What makes network vulnerable?
  - Unkow attacks
    - Attacks may be launched from thousands of miles away.
    - Hack a machine from another hacked machine.
  - Many points of attack: from any machine to any machine
  - Sharing
  - System/Network complexity
  - Unknown perimeter (host on multiple networks)
  - Unknown paths (packets may travel over many different paths to a destination)
- What are the consequences of network attacks?
### **Hazy network perimeter**

## Attacks
– Packet sniffing
– Spoofing: SYN spoofing, how would anti-spoofing help?
– Flooding: UDP flood, SYN flood
– Smurf attack
– DoS attacks: reflection, amplification






























## Controls
– Design: separation, single point of failure, redundancy, recovery, encryption (link vs. end-to-end)
– Protocols: SSL/TLS
■ Provides additional security services
■ From TLS 1.2 to TLS1.3
– Protocols: IPsec
■ Transport Mode vs. Tunnel Mode
■ AH vs. ESP
6Network Security
■ Controls
– Design: separation, single point of failure, redundancy, recovery, encryption (link vs. end-to-end)
– Protocols: SSL/TLS
■ Provides additional security services
■ From TLS 1.2 to TLS1.3
– Protocols: IPsec
■ Transport Mode vs. Tunnel Mode
■ AH vs. ESP
6
Firewall and IDS
■ Firewall
– Types of firewalls: strengths and limitations
– What can be protected, and what cannot?
■ IDS
– Fundamental assumption: intruder behavior differs from legitimate users
– Host-based IDS vs. Network IDS
– Signature-based IDS vs. anomaly detection IDS
– Detection quality, Bayesian detection rate, and the base rate fallacy
7



## Injection
- Cross-Site Scripting(XSS)
- SQL injection
- Problem: lack of input sanitization
  - Classic mistakes in the use of PHP
- PHP is a server scripting language with C-like syntax
  - It can intermingle static HTML and code, embed variables in double-quote strings
  ```php
  <input user=<?php echo $username;?>>
  $username="world";
  ```
- Why we use PHP? Because we want to interact between the user and the server

## XSS
- `Cross-Site Scripting` is a type of computer security vulnerability typically found in web applications. XSS enables attackers to inject client-side scripts into web pages viewed by other users.
- How XSS work?
  - User visit a website
  - The attacker injects a script into the website
  - User click the link that contains the script
  - The website will echo user input
  - User will be redirected to the attacker's website and send the cookie to the attacker
  - 