- Coverage: Lecture 19 to Lecture 22
- Network security (about 60%)
- Firewall and IDS (about 40%)
- Web security (20%)


# Network Security
## Network Vulnerabilities
### **What makes network vulnerable?**
  - `Unkow attacks`
    - Attacks may be launched from thousands of miles away.
    - Hack a machine from another hacked machine.
  - Many points of attack: from any machine to any machine
  - Sharing
  - System/Network complexity
  - Unknown perimeter (host on multiple networks)
  - Unknown paths (packets may travel over many different paths to a destination)
- What are the consequences of network attacks?


### **Hazy network perimeter**
- HAPPENED when it’s difficult to def the boundaries of a network due to factors such as cloud-based services and mobile access.
- PROBLEM: can create vulnerabilities and make it harder to control and monitor activity.
- SOLVE: use tools and strategies suck as network segmentation, access controls, and monitoring to improve network security.
  
## Network Attacks
### Threat Precursors
- Are techniques or activities that can be used by potential attackers to gather information about a network, system, or organization.
- COMMON THREAT: Port scan, war dialers, social engineering, dumpster diving, network mapping, vulnerability scanners, vendor documentation.


### Eavesdropping, Wiretapping
- **Eavesdropping**: the unauthorized interception of information by a third party.
- **Wiretapping**: the interception of telephone communications by a third party.
- TECHNIQUE can be done by using:
  - Packet sniffers: wireshark, ettercap, tcpdump
  - Cable-based: wiretaps, inductance(tap wire, read signals  without physical contact)
  - Insecure wireless networks: also possibility of theft of service

### **Packet Sniffing**
- `Packet sniffing` is the process of capturing and analyzing network traffic. DONE using a packet sniffer tool. Promiscuous mode can be used to read all packet on the network.
- *Ethernal Frame Structure* used to transmit data over Ethernet networks
  - STRUCTURE: preamble, destination MAC address, source MAC address, type, data, and CRC.
  - When a packet is sent over a subnet: all within collision domain read until dst address is found. If the des adress matches the device's address, the packet copied to main memory and the CPU interrupts the OS to process the packet.
  - In *promiscuous mode*, read all packets on the network
  - In *wireless networks*, the Etherneet frame structure is modified to include a wireless header and fields to support wireless communication.

### **Snoofing**
- `Snoofing` is the act of capturing and analyzing network traffic.
- involves falsifying or manipulating the data in a packet to gain unauthorized access to a network or information.
- `Masquerading` involves an attacker pretending to be a different user or device in order to gain unauthorized access to a network or information. CAN BE USED TO DO session hijacking, man in the middle attack, and replay attack.

#### At *Network Layer*: 
- involves Internet Protocol adress with a false address, which can be used to attacks such as phishing and network scanning.
- `ICMP redirect attack` redirect message inform a host of a better route to a destination. CAN BE USED TO redirect traffic to a malicious host. CAN BE PREVENTED by disabling ICMP redirect messages.

#### At *Transport Layer*: 
- involves TCP/IP address with a false address, which can be used to attacks such as phishing and network scanning.
- ACTION: TCP establishes a connection via 3-way handshake
  - X -> S: SYN(ISNx), SRC = T 
  - S -> T: SYN(ISNs), ACK(ISNx)
  - X -> S: ACK(ISNs), SRC = T
  - X -> S: ACK(ISNs), SRC=T,nasty-data
- *Non-blind spoofing*: attack impersonates the client to send ISNx. If attacker X is in the same subnet as the victim, he can simply sniff ISNs. With the correct ISNs, X can impersonate the trusted client T
- *Blind spoofing*: if attack in a different network, he cannot sniff the sequence number and acknowledgement number. He need to predict ISNs of the server(Known as *Sequence Number Prediction*)

### After Spoofing
- Man in the middle attack: beffore session starts. 
- Session hijacking: after session starts. CAUSE: corrupt an established connection and re-establish it using the corrupted sequence number.
- Denial of service: can be direct DoS attacks(ICMP destination unreachable attacks). Spoofing help to hide the attacker's identity.
  
### DoS (attack from a single source) and DDoS (attack from multiple sources)
- An action that prevents or impairs the authorized use of networks, systems, or applications by exhausting resources.
- Attack on avalability of some resources
  - Network bandwidth: flood the network with bogus traffic
  - System resources: overload or crash network devices
  - Application Resources: crash or overload application
- DoS: ping of death, ARP spoofing, SYN spoofing, Flooding
- *Ping of Death* send oversize ICMP datagrams to the victim. The victim's system will crash, freeze, or reboot.

### Source Address Spoofing (a type of DoS attack)
- technique used by attackers to falsify the source IP address of their network traffic, make it appear like it is coming from a trusted source. 
- PURPOSE: use to deceivee and mislead the victim and evade detection or gain access to a network.
- SOLUTION: study backscatter traffic to detect DoS attacks.In honeynet, advertise routes to unused IP addresses to monitor attack traffic.

### TCP SYN spoofing (a type of DoS attack)
- An attack that spoofs the source IP aadress of a TCP SYN packet to prevent the establishment of a TCP connection and consume server resources.
- PREVENT: SYN cookies, firewall.


### SYN spoofing (a type of DoS attack)
- A defense technique can be used to prevent SYN flooding attacks by immediately tearing down half-open connections.

### Flooding (a type of DoS attack)
- A type of DoS attack that sends a large number of connection or information requests to a target.
- Any type of network packet can be used to flood DoS attacks.
- PING flood: send a large number of ICMP echo requests to a victim.
- **UDP flood** uses large number of UDP packets directed to some port number on the target system: server needs to respond
- **TCP SYN flood** uses large number of TCP SYN packets to a victim: server needs to respond with SYN-ACK
- *Countermeasure*: detect spoofing, packet filtering

### Reflection (a type of DoS attack)
- GOAL: overwhelm the target'network resources with a large volume of traffic, make it unavailable to legitimate users.
- attacker sends request packets with a *spoofed source address*1 of the victim, to a known service at the *intermediary*2 to generate *response packets*3 to the victim.
  - 1: response packets go to the target
  - 2: if requests in a smaller size result in responses in a large size, it's an amplification attack.
  - 3: intermediary is of high capacity
- *Countermeasure*: detect spoofing, blocking spoofed packets, packet filtering

### Amplification (a type of DoS attack)
- A type of network-based attack that uses a large number of requests to overwhelm the target's network resources.
#### **Smurf attack**
- Attacker spoofs the IP source address as the victim’s IP. Sends a PING request to a broadcast address.



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
  