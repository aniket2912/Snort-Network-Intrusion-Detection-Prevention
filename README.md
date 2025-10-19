# 🐍 Snort – Network Intrusion Detection & Prevention

## 📌 Overview  
Snort is a powerful open-source **Network Intrusion Detection and Prevention System (NIDS/NIPS)** capable of analyzing network traffic in real-time. It uses a combination of **packet sniffing, logging, and signature-based rules** to detect and prevent malicious activities within a network.  

This module focuses on installing, configuring, and using Snort to detect and respond to suspicious traffic.  

---

## 🎯 Objectives  
- Understand Snort architecture and working principles  
- Configure Snort in **sniffer, packet logger, and IDS/IPS modes**  
- Write and test **custom Snort rules**  
- Analyze network traffic using Snort alerts and logs 
- Detect common network attacks (e.g., port scanning, DoS, buffer overflow attempts)  

---

## 🛠️ Features of Snort  
- Packet sniffing and traffic logging  
- Signature-based detection using rules  
- Protocol analysis and anomaly detection  
- Real-time intrusion prevention (IPS mode)  
- Flexible rule-writing capabilities  

---

## 📂 Contents  
- **Installation & Setup** – Step-by-step guide to install Snort on Linux  
- **Configuration Files** – Snort.conf customization  
- **Snort Modes** – Sniffer, Logger, and IDS/IPS  
- **Custom Rules** – Writing and testing detection rules  
- **Lab Exercises** – Hands-on practice with simulated attacks  
- **Logs & Alerts** – Analyzing Snort output  

---

## 📝 Example Snort Rules  

### Detect ICMP (Ping) traffic:
alert icmp any any -> any any (msg:"ICMP Packet Detected"; sid:1000001; rev:1;)

    ### Detect Nmap scan:
alert tcp any any -> any 80 (flags:S; msg:"Nmap SYN Scan Detected"; sid:1000002; rev:1;)

---

## 📊 Lab Exercises  
1. Configure Snort in **sniffer mode** and capture live traffic.  
2. Run Snort in **packet logger mode** and analyze logs.  
3. Write **custom Snort rules** to detect ICMP, TCP, and UDP attacks.  
4. Simulate attacks (e.g., Nmap scan, DoS) and verify alerts.  
5. Test Snort in **inline IPS mode** to block malicious traffic.  

---

## 📖 References  
- [Snort Official Website](https://www.snort.org/)  
- [Snort Documentation](https://www.snort.org/documents)  
- [Snort Rules Community](https://www.snort.org/downloads#rules)  

---
