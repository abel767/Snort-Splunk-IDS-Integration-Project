# Snort and Splunk IDS Integration Project

This repository documents the successful deployment and configuration of an Intrusion Detection System (IDS) solution using **Snort** on an Ubuntu server, integrated with **Splunk Enterprise** for centralized log aggregation and analysis.

The system is designed to detect and alert on common attack vectors, such as **port scanning** and **SSH brute-force attempts**, providing real-time visibility into network security events.

---

### Key Components

| Component | Role | Host Operating System |
| :--- | :--- | :--- |
| **Snort IDS** | Network Intrusion Detection and Alerting | Ubuntu Server (Virtual Machine) |
| **Splunk Universal Forwarder (UF)** | Agent to collect and forward Snort logs | Ubuntu Server (Virtual Machine) |
| **Splunk Enterprise** | Log Indexing, Analysis, and Visualization | Host Operating System (Windows 11) |
| **Attacker Host** | Used for testing custom detection rules | Kali Linux (Virtual Machine) |

### Network Environment

The solution operates within a private, bridged network where all hosts can communicate.

| Host Role | Placeholder IP |
| :--- | :--- |
| **Snort Host / UF** | `SNORT_HOST_IP` |
| **Splunk Indexer** | `SPLUNK_INDEXER_IP` |
| **Network Range** | `192.168.1.0/24` (Example HOME_NET) |

### Documentation Structure

This project includes detailed documentation to guide setup, configuration, and analysis:

* **`docs/Master_Playbook.md`**: The complete step-by-step record of all successful commands and configurations.
* **`docs/Installation_Guide.md`**: A focused guide for setting up the environment.
* **`docs/Architecture.md`**: Visual and descriptive overview of the system design.
* **`docs/SPL_Queries.md`**: Essential Splunk Search Language (SPL) for security analysis.

---

### 💡 Next Steps

To dive into the configuration details and deployment steps, please start with the **[Master Playbook](docs/Master_Playbook.md)**.
