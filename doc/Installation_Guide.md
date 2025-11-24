
#  Installation Guide: Snort-Splunk Integration Setup

This guide provides step-by-step instructions for setting up the environment, focusing on the configuration of the Snort Host and the connection to the Splunk Indexer.


### 1. Environment Setup

| Host Role | OS/Platform | Network Configuration | Placeholder IP |
| :--- | :--- | :--- | :--- |
| **Snort Host / UF** | Ubuntu Server 24.04.03 (VM) | Bridged Adapter (Allows network communication) | `$$SNORT_HOST_IP$$` |
| **Splunk Indexer** | Windows 11 (Host Machine) | Requires network access to the VM subnet. | `$$SPLUNK_INDEXER_IP$$` |
| **Attacker Host** | Kali Linux (VM) | Bridged Adapter | N/A (Used for testing) |

**Prerequisite on Splunk Indexer (SPLUNK\_INDEXER\_IP):** Ensure a **Splunk Receiving Port** (e.g., 9997) is configured and open in the Indexer's firewall settings.

---

### 2.  Snort and Universal Forwarder (UF) Setup (On Ubuntu Server: `SNORT_HOST_IP`)

#### 2.1 Snort Installation and Initial Config

1.  **Install Snort:**
    ```bash
    sudo apt update
    sudo apt install snort -y
    ```
2.  **Configure Local Network (`/etc/snort/snort.conf`):**
    Open the configuration file and set your internal network range (HOME\_NET).
    ```bash
    # Use nano or your preferred editor
    sudo nano /etc/snort/snort.conf
    # Change:
    # var HOME_NET any
    # To:
    var HOME_NET 192.168.1.0/24
    ```
3.  **Define Alert Log Path (`/etc/snort/snort.conf`):**
    Ensure Snort writes alerts to the specific file the UF will monitor.
    ```bash
    # Locate and modify the 'output alert_fast' line:
    output alert_fast: /var/log/snort/alert.log
    ```

#### 2.2 Deploy Custom Snort Rules

1.  **Create/Edit Custom Rules File:**
    ```bash
    sudo nano /etc/snort/rules/local.rules
    ```
2.  **Paste Custom Rules (Example: SYN Scan):**
    ```snort
    alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ATTACK: Rapid Port Scan Attempt Detected (SYN)"; flags:S; flow:stateless; detection_filter: track by_src, count 10, seconds 60; sid:1000015; rev:1;)
    ```
3.  **Test and Start Snort:**
    ```bash
    sudo snort -c /etc/snort/snort.conf -T  # Test
    sudo snort -D -c /etc/snort/snort.conf -i <Your_Interface> # Start Daemon (e.g., enp0s3)
    ```

#### 2.3 Splunk Universal Forwarder Setup

1.  **Install UF:**
    Assuming `splunkforwarder.deb` is downloaded:
    ```bash
    sudo dpkg -i splunkforwarder.deb
    sudo /opt/splunkforwarder/bin/splunk start --accept-license
    # Follow prompts to set admin credentials
    ```
2.  **Configure Forwarding to Indexer (`/opt/splunkforwarder/etc/system/local/outputs.conf`):**
    ```bash
    [tcpout]
    defaultGroup = default-autolb-group

    [tcpout:default-autolb-group]
    server = $$SPLUNK_INDEXER_IP$$:9997
    ```
3.  **Configure Log Monitoring (`/opt/splunkforwarder/etc/system/local/inputs.conf`):**
    ```bash
    [monitor:///var/log/snort/alert.log]
    disabled = false
    sourcetype = snort_alert_fast
    index = main
    ```
4.  **Restart UF:**
    ```bash
    sudo /opt/splunkforwarder/bin/splunk restart
    ```

---

### 3. 🧪 Validation (On Attacker Host and Splunk)

1.  **Generate Test Traffic (On Kali Linux):**
    Use the attacker machine to trigger the Snort rules.
    ```bash
    # Example to trigger the SYN Scan rule (SID 1000015)
    sudo nmap -sS -p 1-1000 -T4 $$SNORT_HOST_IP$$
    ```
2.  **Verify Logs:**
    * Check `/var/log/snort/alert.log` on the Snort Host for new alerts.
    * Check Splunk Enterprise using the basic query: `index=main sourcetype=snort_alert_fast`
    * If logs appear, the integration is successful. Proceed to the [SPL Queries](SPL_Queries.md) for analysis.
