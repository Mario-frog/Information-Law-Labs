# Information Law Labs

Laboratory work for the course "Information Law": practical tasks, software implementations, and results. The focus is on networking and information security: sockets, protocols, cryptography, authentication, and intrusion prevention systems.

## Contents

| Folder | Topic | Main technologies |
|--------|-------|-------------------|
| [Lab-01](Lab-01) | TCP server and client | Python, `socket` |
| [Lab-02](Lab-02) | UDP server and client, TCP vs UDP comparison, packet loss | Python, `socket`, `csv` |
| [Lab-03](Lab-03) | ARP protocol: network scanning, visualization, ARP spoofing detection | Python, Scapy, NetworkX, Matplotlib |
| [Lab-04](Lab-04) | Network data protection: SSH tunnels, AES-GCM, RSA-PSS, HMAC | Python, `cryptography`, OpenSSH |
| [Lab-05](Lab-05) | Zero-knowledge authentication (Feige-Fiat-Shamir) | Python, `secrets` |
| [Lab-06](Lab-06) | Network attack analysis with an IPS | Suricata, Nmap, hping3, sqlmap, Metasploit |

## Repository structure

Each `Lab-XX` folder usually contains:

- source code of the programs;
- supporting files (dependencies, rules, example output);
- the lab report in `.docx` format.

## Requirements

- Python 3.8+
- Dependencies of individual labs are listed in the `requirements.txt` file of the corresponding folder (where needed).
- Lab-03 requires administrator privileges (ARP scanning) and, on Windows, Npcap.
- Lab-06 requires virtual machines (attacker and protected host) in an isolated network.

## Quick start

```bash
git clone https://github.com/Mario-frog/Information-Law-Labs.git
cd Information-Law-Labs/Lab-XX      # replace XX with the lab number
pip install -r requirements.txt     # if the folder has this file
python <script_name>.py             # see the lab report or the folder for the exact script and arguments
```

## Security notice

The materials are for educational purposes only. Scanning, attack simulation, and other actions described in Lab-03 and Lab-06 must be performed only in your own isolated lab network or with the system owner's permission. Do not use these materials against third-party resources.
