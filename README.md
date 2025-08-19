# 🛡️ SOC Analyst L1 Lab Setup

## Table of Contents
1. [Introduction](#introduction)
2. [Lab Requirements](#lab-requirements)
3. [Network Architecture](#network-architecture)
4. [Tools and Software](#tools-and-software)
5. [Lab Setup Steps](#lab-setup-steps)
    - [1. Environment Setup](#1-environment-setup)
    - [2. Log Sources Configuration](#2-log-sources-configuration)
    - [3. SIEM Setup](#3-siem-setup)
    - [4. Alerting and Dashboard](#4-alerting-and-dashboard)
    - [5. Incident Response Lab](#5-incident-response-lab)
6. [Sample Commands](#sample-commands)
7. [References](#references)

---

## Introduction
A SOC Analyst L1 monitors security alerts and responds to incidents. This lab is designed to simulate a real-world SOC environment for learning and practice.

---

## Lab Requirements
- **Host OS:** Windows 10/11 or Linux (Ubuntu)
- **Virtualization:** VMware Workstation or VirtualBox
- **Memory:** Minimum 16GB RAM
- **CPU:** 4 cores
- **Disk Space:** 200GB free
- **Internet:** Optional for downloading tools

---

## Network Architecture

```text
            +-------------------+
            |  SOC Analyst VM   |
            |  (Kali/Ubuntu)    |
            +-------------------+
                    |
                    | LAN
                    |
+-------------------+-------------------+
|   Log Sources / Servers                |
| - Windows Server (Event Logs)          |
| - Linux Server (Syslogs)               |
| - Firewall / Router                     |
| - IDS/IPS                               |
+----------------------------------------+
````

---

## Tools and Software

* **SIEM:** Wazuh, Splunk (Trial)
* **Endpoint Tools:** Osquery, Sysinternals Suite
* **Networking & Security Tools:** Wireshark, Nmap
* **Alert Testing:** Metasploit, Kali Linux
* **Log Generators:** NXLog, Filebeat

---

## Lab Setup Steps

### 1. Environment Setup

1. Install VMware/VirtualBox on host machine.
2. Create virtual machines:

   * **SOC Analyst VM:** Ubuntu 22.04 or Windows 10
   * **Windows Server VM:** Domain Controller, Event Log generator
   * **Linux VM:** Syslog generator
   * **Firewall/Router VM:** pfSense or similar
3. Configure network adapter as **Internal Network** to simulate LAN.

---

### 2. Log Sources Configuration

1. **Windows Server:**

   ```powershell
   # Enable Windows Event Forwarding
   wecutil qc
   ```
2. **Linux Server:**

   ```bash
   sudo apt install rsyslog
   sudo systemctl enable rsyslog
   sudo systemctl start rsyslog
   ```
3. Configure devices to forward logs to the SIEM VM.

---

### 3. SIEM Setup

#### Wazuh Installation (Ubuntu)

```bash
# Add Wazuh repository
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo apt-key add -
echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt update
sudo apt install wazuh-manager wazuh-agent
sudo systemctl enable wazuh-manager
sudo systemctl start wazuh-manager
```

#### Splunk Installation (Optional)

```bash
wget -O splunk.tgz 'https://download.splunk.com/products/splunk/releases/10.0.0/linux/splunk-10.0.0-Linux-x86_64.tgz'
tar -xvzf splunk.tgz -C /opt
/opt/splunk/bin/splunk start --accept-license
```

---

### 4. Alerting and Dashboard

* Configure dashboards in Wazuh/Splunk for:

  * Failed login attempts
  * Malware detection
  * Suspicious network traffic
* Create alerts for:

  * Port scanning
  * Brute force attempts
  * Privilege escalation

---

### 5. Incident Response Lab

1. Generate events using Kali Linux:

   ```bash
   nmap -sS 192.168.142.0/24
   hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.168.142.130 ssh
   ```
2. Observe generated alerts on SIEM dashboard.
3. Investigate logs and document findings.
4. Perform containment and remediation exercises.

---

## Sample Commands

```bash
# Check agent status
sudo systemctl status wazuh-agent

# Tail Wazuh alerts
tail -f /var/ossec/logs/alerts/alerts.json

# Test network connectivity
ping 192.168.142.130

# Capture network packets
sudo tcpdump -i eth0
```

---

## References

* [Wazuh Documentation](https://documentation.wazuh.com/)
* [Splunk Tutorial](https://www.splunk.com/en_us/training.html)
* [Kali Linux Tools](https://www.kali.org/tools/)
* [Microsoft Event Forwarding](https://docs.microsoft.com/en-us/windows/security/threat-protection/use-event-forwarding-to-assist-in-monitoring)

```

