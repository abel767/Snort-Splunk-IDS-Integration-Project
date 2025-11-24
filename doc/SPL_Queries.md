# SPL Queries: Snort Log Analysis in Splunk

This document contains essential Splunk Search Processing Language (SPL) queries used to effectively parse, categorize, and visualize the security events forwarded from the Snort IDS.

---

### 1. Initial Validation Search

This simple query confirms that the Universal Forwarder is successfully sending logs to the Indexer with the correct metadata.

```splunk
index=main sourcetype=snort_alert_fast
| sort -_time
| head 10
```
**Purpose: Displays the 10 most recent Snort events to confirm data flow and check the raw log format.**

### 2. Robust Attack Analysis and Visualization Query
This is the primary query used to extract key information, categorize attacks based on Snort's Signature ID (SID), and generate statistics suitable for a security dashboard.

```splunk
# 1. Base Search & Filtering
index=main sourcetype=snort_alert_fast
| search "Rapid Port Scan" OR "Excessive SSH Failures"

# 2. Field Extraction (REGEX)
# Extracts the Attacker's IP from the log line format: A.B.C.D:Port ->
| rex "(?<Attacker_IP>\d+\.\d+\.\d+\.\d+):\d+ ->"
# Extracts the Signature ID (SID) from the format: [**:SID:**]
| rex "\[\*\*\]\s\[\d+:(?<Signature_ID>\d+):\d+\]"

# 3. Categorization (EVAL/Case)
# Maps the extracted numerical SID to a readable attack name
| eval Attack_Name=case(
    Signature_ID=="1000015", "NMAP SYN Scan",
    Signature_ID=="1000012", "SSH Brute Force",
    true(), "Other Custom Attack"
)

# 4. Aggregation and Presentation
# Counts the total number of attacks per category
| stats count AS Total_Attacks BY Attack_Name
# Sorts the results to show the most frequent attacks first
| sort -Total_Attacks
```
**Purpose: Creates a table or chart showing the count of each custom-defined attack type, enabling analysts to quickly identify the most active threats.**

### 3. Top Attacker Identification Query
This query identifies which source IPs are generating the most alerts for a specific attack type, aiding in potential firewall blocklist creation.

```splunk
index=main sourcetype=snort_alert_fast Signature_ID="1000012"
# Extracts Attacker_IP from the log
| rex "(?<Attacker_IP>\d+\.\d+\.\d+\.\d+):\d+ ->"
# Groups by the extracted IP and counts the total alerts
| stats count BY Attacker_IP
| rename count AS "SSH Brute Force Attempts"
| sort -"SSH Brute Force Attempts"
| top 10 Attacker_IP
```

**Purpose: Quickly identifies the Top 10 source IPs attempting SSH brute force against the network.**
