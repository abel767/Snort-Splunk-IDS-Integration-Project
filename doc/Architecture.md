# Architecture: Snort–Splunk IDS Integration

This document describes the architecture of the Snort–Splunk IDS pipeline, including all systems involved, their roles, and the complete data flow from detection to visualization. The structure matches the format used in the Master Playbook.

---

## 1. Environment Summary

The project environment consists of four systems working together to detect, forward, index, and analyze intrusion detection alerts.

* Snort IDS on Ubuntu Server 24.04
* Splunk Universal Forwarder on Ubuntu Server 24.04
* Splunk Enterprise (Indexer + Search Head) on Windows 11 (host machine)
* Kali Linux attacker machine in VirtualBox

Ubuntu Server and Kali Linux both run inside VirtualBox. Windows 11 hosts Splunk Enterprise.

---

## 2. System Components and Roles

### 2.1 Snort IDS (Ubuntu Server 24.04)

* Performs network intrusion detection.
* Applies custom rules to inspect traffic.
* Generates alerts in fast format.
* Stores alerts at:

  ```
  /var/log/snort/alert.log
  ```
* Alerts are consumed by the Splunk Universal Forwarder.

### 2.2 Splunk Universal Forwarder (Ubuntu Server 24.04)

* Monitors Snort's alert.log file.
* Forwards alerts to Splunk Enterprise over port 9997.
* Uses two configurations:

  * `inputs.conf` for file monitoring
  * `outputs.conf` for forwarding rules

### 2.3 Splunk Enterprise (Windows 11)

* Acts as the indexing and searching layer.
* Receives logs and stores them under the chosen index.
* Provides dashboards, analytics, and SPL search functionality.

### 2.4 Kali Linux (VirtualBox)

* Used to simulate real-world attacks.
* Generates port scans, brute force attempts, and custom traffic.
* Sends traffic directly to Ubuntu Snort machine.

---

## 3. Network Architecture

### 3.1 Virtualization Layout

* Windows 11 serves as the host operating system.
* VirtualBox runs:

  * Ubuntu Server 24.04 (Snort + Splunk Forwarder)
  * Kali Linux (Attacker)
* All machines share the same VirtualBox network.

### 3.2 Network Communication Overview

* Kali sends network traffic to Ubuntu Server.
* Snort inspects packets and logs alerts.
* Splunk Forwarder forwards alert data to Splunk Enterprise.
* Splunk Enterprise indexes and displays the data.

---

## 4. Data Flow Architecture

The following flow represents how attack events travel through the system:

```
[ Kali Linux Attacker ]
            |
            v
[ Ubuntu Server - Snort IDS ]
  - Generates /var/log/snort/alert.log
            |
            v
[ Splunk Universal Forwarder ]
  - Monitors alert.log
  - Sends data to Indexer over 9997
            |
            v
[ Splunk Enterprise (Windows 11) ]
  - Receives and indexes events
  - Dashboards and searches show Snort alerts
```

---

## 5. Logical Architecture Summary

| Layer            | Component                  | Description                            |
| ---------------- | -------------------------- | -------------------------------------- |
| Detection Layer  | Snort IDS                  | Detects attacks, generates alerts      |
| Forwarding Layer | Splunk Universal Forwarder | Sends alerts to Indexer                |
| Indexing Layer   | Splunk Enterprise          | Stores and processes the events        |
| Analysis Layer   | Splunk Search/Dashboards   | Visualizes and analyzes intrusion data |

---

## 6. Architecture Goals

* Provide a complete IDS pipeline from detection to visualization.
* Use real attack traffic for realistic testing.
* Maintain clear separation between detection, forwarding, indexing, and analysis layers.
* Allow dashboards to display meaningful threat intelligence.

---

End of Architecture Document.

