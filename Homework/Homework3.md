# Homework 3
- Name: Nguyen Cat Nguyen
- KUID: 3077463
## Network Security
### 1. Assume an attacker controls a large botnet. He wants to attack a victim web server.
1. He wants to use the TCP SYN flooding attack. Please describe how this attack works.
2. Suppose the victim web server uses SYN cookies to protect itself. Will the attack still succeed? Why or why not?
3. The attacker then wants to use the TCP flooding attack. Will this attack work? Why or why not?
### 2. What is amplification DDoS attack? Choose one UDP-based amplification attack as an example to explain how it is amplified. 
### 3. Link-to-link encryption and end-to-end encryption can be used to protect data transmitted over networks. Which means is used by VPN? 
### 4. What security services are provided by TLS? Choose one attack and explain how TLS prevents it. 
### 5. What security services are provided by IPsec? Choose one attack and explain how IPsec prevents it. Can it also be prevented by TLS?
## Firewall and IDS
### 6. The table below shows a packet firewall ruleset that allows inbound and outbound SMTP traffic.
| Rule | Direction | SRC Address | Protocol | Dest Port | Action |
|------|-----------|-------------|----------|-----------|--------|
| A    | in        | External    | TCP      | 25        | Permit |
| B    | out       | Internal    | TCP      | >1023     | Permit |
| C    | in        | Internal    | TCP      | 25        | Permit |
| D    | out       | External    | TCP      | >1023     | Permit |
| E    | Either    | Any         | Any      | Any       | Deny   |

1. Describe the effect of each rule.
2. 