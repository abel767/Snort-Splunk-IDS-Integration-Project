# Architecture: Snort-Splunk IDS Integration

This document outlines the logical and physical architecture of the deployed Intrusion Detection System (IDS) and log analysis platform.

---

## 1. High-Level System Diagram

The system operates as a classic three-tiered structure: **Attacker**, **IDS/Forwarder**, and **Indexer/Analyzer**.



---

## 2. Component Roles and Interaction

### A. The Snort Host (Intrusion Detection)

* **Host:** Ubuntu Server (`SNORT_HOST_IP`)
* **Component:** **Snort**
    * **Role:** Performs real-time packet inspection against a set of predefined and custom rules (e.g., SID 1000015 for port scans).
    * **Function:** Generates alerts for suspicious network activity and writes them to the specified log file (`/var/log/snort/alert.log`) in the `alert_fast` format.
* **Component:** **Splunk Universal Forwarder (UF)**
    * **Role:** Acts as the log collection agent.
    * **Function:** Continuously monitors the Snort alert file (`inputs.conf`) and securely transmits (forwards) the data via TCP on port 9997 (`outputs.conf`) to the Splunk Indexer.

### B. The Splunk Indexer (Centralized Analysis)

* **Host:** Windows 11 Host (`SPLUNK_INDEXER_IP`)
* **Component:** **Splunk Enterprise** (Indexer and Search Head combined)
    * **Role:** Data ingestion, indexing, storage, and analysis.
    * **Function:**
        1.  **Ingestion:** Listens on port **9997** to receive data from the UF.
        2.  **Indexing:** Stores the raw Snort log data, assigning metadata like `sourcetype=snort_alert_fast` and `index=main`.
        3.  **Analysis:** Allows security analysts to query the indexed data using the Splunk Search Processing Language (SPL) to create visualizations, reports, and dashboards.

### C. External Hosts

* **Attacker Host (Kali Linux):** Used to generate malicious traffic (e.g., Nmap scans, brute-force attempts) to test the efficacy of the Snort ruleset and the end-to-end integration pipeline.
* **Internal Network (`HOME\_NET`):** The protected network segment (e.g., `192.168.1.0/24`) that Snort is deployed to monitor and defend.
