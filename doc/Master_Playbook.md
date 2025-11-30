# Master Playbook: Snort-Splunk IDS Integration

This document serves as the comprehensive, unedited record of every successful command and configuration used during the Snort IDS and Splunk Universal Forwarder (UF) deployment.

---

### Phase 1: Snort Installation and Core Configuration

This phase details the setup of the Snort IDS on the dedicated Ubuntu Server (`$$SNORT_HOST_IP$$`).

#### 1. Installation and Network Setup

| Action | Command/Configuration | Notes |
| :--- | :--- | :--- |
| **Install Snort Package** | `sudo apt install snort -y` | Installs the available stable package (typically 2.9.x) and dependencies. |
| **Define HOME\_NET** | Edit `/etc/snort/snort.conf`: `var HOME_NET 192.168.1.0/24` | **Crucial:** Defines the protected local subnet (Snort's 'home'). |
| **Configure Logging Path** | Edit `/etc/snort/snort.conf`: `output alert_fast: /var/log/snort/alert.log` | **CRITICAL:** Sets the absolute path for the **Fast Alert** log format, which will be monitored by the UF. |

**Define Home_net** 
<br>
<img src="https://github.com/abel767/Snort-Splunk-IDS-Integration-Project/blob/0c1c9d2338ee8c2782f40d7a883f294eb0ded24e/Images/Snort/Home_net.png" width="600" height="350">

**Configure Logging Path**
<br>
<img src="https://github.com/abel767/Snort-Splunk-IDS-Integration-Project/blob/0c1c9d2338ee8c2782f40d7a883f294eb0ded24e/Images/Snort/output_alert.png" width="600" height="350">


#### 2. Final Custom Ruleset Configuration

The following rules were added to the custom rules file at `/etc/snort/rules/local.rules` to detect specific attack patterns.

| Rule SID | Snort Rule Line | Notes |
| :--- | :--- | :--- |
| **1000015** | `alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ATTACK: Rapid Port Scan Attempt Detected (SYN)"; flags:S; flow:stateless; detection_filter: track by_src, count 10, seconds 60; sid:1000015; rev:1;)` | Rate-limits SYN packets (10 in 60 seconds) from a single source to detect SYN scans. |
| **1000012** | `alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"ATTACK: Excessive SSH Failures from Source IP (Brute Force - Content Check)"; content:"SSH-2.0-"; flow:to_server,established; detection_filter: track by_src, count 8, seconds 60; sid:1000012; rev:2;)` | Detects an excessive number of SSH-related connection attempts (8 in 60 seconds) targeting port 22. |
| **1000010** | `alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ATTACK: NULL Scan Probe Detected"; flags:!UAPRSF; flow:stateless; sid:1000010; rev:3;)` | Detects TCP packets with *no* flags set (NULL Scan). Uses the corrected `!UAPRSF` flag syntax. |

<img src="https://github.com/abel767/Snort-Splunk-IDS-Integration-Project/blob/07d7c6bd9f2397474ec2a4462432dfbc972652e9/Images/Snort/rules.png" width="600" height="350">


#### 3. Deploy Snort Service

Ensure Snort is running as a background daemon and monitoring the correct interface.

```bash
# 1. Test the Configuration for Errors (Must Pass)
sudo snort -c /etc/snort/snort.conf -T

# 2. Start the Snort IDS Daemon
# Replace 'enp0s3' with the correct network interface name on your server
sudo snort -D -c /etc/snort/snort.conf -i enp0s3
```
<img src="https://github.com/abel767/Snort-Splunk-IDS-Integration-Project/blob/216ed80ee73fac5fe753cd7818ff7bbf047e7fe0/Images/Snort/starting%20snort.png" width="600" height="350">


### Phase 2: Splunk Universal Forwarder (UF) Setup
This phase involves installing the UF on the Snort Host and configuring it to send the Snort log file to the Splunk Indexer (SPLUNK_INDEXER_IP).

#### 1. UF Installation and Startup
```bash
# 1. Install UF package (assuming the .deb file is downloaded in the current directory)
sudo dpkg -i splunkforwarder.deb

# 2. Start the UF and set the initial administrator credentials
sudo /opt/splunkforwarder/bin/splunk start --accept-license
```

#### 2. Configure Forwarding (outputs.conf)
This configuration directs all forwarded data to the Splunk Indexer over port 9997.
```Bash
# Edit or create the outputs.conf file
sudo nano /opt/splunkforwarder/etc/system/local/outputs.conf
```

**Content saved in file:**
```bash
[tcpout]
defaultGroup = default-autolb-group

[tcpout:default-autolb-group]
server = $$SPLUNK_INDEXER_IP$$:9997
```

<img src="https://github.com/abel767/Snort-Splunk-IDS-Integration-Project/blob/216ed80ee73fac5fe753cd7818ff7bbf047e7fe0/Images/Snort/splunkF-outputsConfig.png" width="600" height="350">


#### 3. Configure Monitoring (inputs.conf)
This configuration instructs the UF to monitor the Snort alert log file and assign the correct metadata.
```Bash
# Edit or create the inputs.conf file
sudo nano /opt/splunkforwarder/etc/system/local/inputs.conf
```

**Content saved in file:**
```Bash
[monitor:///var/log/snort/alert.log]
disabled = false
sourcetype = snort_alert_fast
index = main
```

<img src="https://github.com/abel767/Snort-Splunk-IDS-Integration-Project/blob/216ed80ee73fac5fe753cd7818ff7bbf047e7fe0/Images/Snort/splunkF-inputsConfig.png" width="600" height="350">


**Note: Ensure the snort_alert_fast sourcetype is defined or accepted by your Splunk Indexer.**

#### 4. Final UF Restart
A restart is necessary to apply the new forwarding and monitoring configurations.
```bash
sudo /opt/splunkforwarder/bin/splunk restart
```

### Phase 3: Attack Simulation (Kali Linux)
These commands were executed from the Attacker Host (Kali Linux) to verify that the custom Snort rules (SID 1000015 and SID 1000012) were successfully triggered.

#### 1. Simulate Rapid Port Scan (Triggers SID 1000015)
The following Nmap SYN scan was used to target the Snort Host ($$SNORT\_HOST\_IP$$) and trigger the rate-limiting port scan detection rule.
```bash
# Command executed from Kali Linux 
sudo nmap -sS -p 1-1000 $$SNORT_HOST_IP$$
```

<img src="https://github.com/abel767/Snort-Splunk-IDS-Integration-Project/blob/216ed80ee73fac5fe753cd7818ff7bbf047e7fe0/Images/kali/kali-nmap.png" width="600" height="350">


#### 2. Simulate SSH Brute Force (Triggers SID 1000012)
The Hydra tool was used to attempt rapid, failed SSH logins, triggering the protocol-aware brute force detection rule.

```bash
# Command executed from Kali Linux
sudo hydra -L users.txt -P passwords.txt -t 16 $$SNORT_HOST_IP$$ ssh
```

<img src="https://github.com/abel767/Snort-Splunk-IDS-Integration-Project/blob/216ed80ee73fac5fe753cd7818ff7bbf047e7fe0/Images/kali/kali-hydra.png" width="600" height="350">




### Phase 4: Validation and Final Splunk Analysis
After confirming that the Splunk Indexer is receiving data (via listening on port 9997), the final step is to analyze the data.

<img src="https://github.com/abel767/Snort-Splunk-IDS-Integration-Project/blob/216ed80ee73fac5fe753cd7818ff7bbf047e7fe0/Images/splunk/Indexer.png" width="600" height="350">


#### 1. Final SPL Query for Dashboard Visualization
This robust Splunk Search Language (SPL) query extracts relevant fields from the Snort logs, maps Signature IDs to human-readable names, and calculates attack statistics.
```Bash
index=main sourcetype=snort_alert_fast
| search "Rapid Port Scan" OR "Excessive SSH Failures"
| rex "(?<Attacker_IP>\d+\.\d+\.\d+\.\d+):\d+ ->"
| rex "\[\*\*\]\s\[\d+:(?<Signature_ID>\d+):\d+\]"
| eval Attack_Name=case(
    Signature_ID=="1000015", "NMAP SYN Scan",
    Signature_ID=="1000012", "SSH Brute Force",
    true(), "Other Custom Attack"
)
| stats count AS Total_Attacks BY Attack_Name
| sort -Total_Attacks
```

<img src="https://github.com/abel767/Snort-Splunk-IDS-Integration-Project/blob/216ed80ee73fac5fe753cd7818ff7bbf047e7fe0/Images/splunk/spl-visualization.png" width="600" height="350">

**(This query is further detailed in SPL_Queries.md)**

---

### Phase 5: Final Splunk Actions (Dashboard Creation)

This phase documents the final steps necessary to make the analysis permanent and easily accessible via a **Splunk Dashboard**.

#### 1. Save Visualization as Dashboard Panel

This action converts the successful search into a permanent monitoring widget, creating the foundation for a Security Operations Center (SOC) dashboard.

| Action | Steps in Splunk GUI | Notes |
| :--- | :--- | :--- |
| **Save Search** | 1. Click **'Save As'** > **'Dashboard Panel'** on the search results page. | Saves the current SPL query and visualization settings. |
| **Name Panel** | Name the panel (e.g., **'Snort IDS Attack Overview'**). | Descriptive name for the widget. |
| **Select Dashboard** | Select **'New Dashboard'** (e.g., **'Snort IDS Monitor'**). | Creates the new dashboard instance. |
| **Finalize** | Select **'Pie Chart'** visualization type. | Saves the panel using the **Pie Chart** visualization you created. |

<img src="https://github.com/abel767/Snort-Splunk-IDS-Integration-Project/blob/8be929b259d99109431311fa051a9a0467033818/Images/splunk/dashboard.png" width="600" height="350">


