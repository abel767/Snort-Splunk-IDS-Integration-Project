# Snort-Splunk IDS Integration

This repository documents the complete setup, configuration, and validation steps for integrating Snort IDS with Splunk for security event monitoring. The project includes the Snort host configuration, log forwarding via the Splunk Universal Forwarder, and Splunk-side parsing and visualization.

## Overview

This integration provides a functional IDS pipeline where Snort generates alerts that are forwarded to Splunk for indexing, analysis, and dashboard reporting. The documentation includes setup guides, playbooks, architecture, and SPL queries.

## Documentation Structure

All detailed guides are located inside the `docs/` directory.

```
README.md
/docs
   Master_Playbook.md
   Installation_Guide.md
   Architecture.md
   SPL_Queries.md
```

## Components

* Snort (Intrusion Detection System)
* Splunk Universal Forwarder (Log forwarding agent)
* Splunk Indexer

## Features

* Custom Snort rule deployment
* Forwarding Snort alert logs to Splunk
* Regex-based extraction of attacker IPs and signature IDs
* Dashboard-ready SPL queries

## Requirements

* Ubuntu Server (Snort Host)
* Splunk Indexer
* Splunk Universal Forwarder
* Snort 2.9.x

## Usage

Refer to the individual guides inside the `docs/` folder:

* Master Playbook for a complete command reference
* Installation Guide for setup steps
* Architecture for deployment understanding
* SPL Queries for analysis and dashboard references

## License

This project is provided for learning and demonstration purposes.

## Introduction

This project demonstrates how to build a functional IDS monitoring pipeline using Snort as the detection engine and Splunk as the indexing and visualization system. It documents every step performed during the deployment, including installation, configuration, file paths, rule management, log forwarding, and SPL-based analysis.

The goal is to provide clarity, reproducibility, and a reference-quality guide for cybersecurity students or analysts building an IDS lab.

## Project Goals

* Deploy Snort with custom, production-style rules.
* Enable structured and reliable log forwarding using Splunk Universal Forwarder.
* Normalize Snort alert logs for better extraction and reporting.
* Visualize alerts using Splunk dashboards.
* Create a repeatable setup for testing attacks like port scanning and SSH brute-force attempts.

## System Environment

This deployment was tested using the following setup:

* **Snort Host:** Ubuntu Server 24.04 running Snort and Splunk Universal Forwarder
* **Splunk Enterprise:** Installed on the Windows 11 host machine
* **Attack Machine:** Kali Linux (VirtualBox)
* **Virtualization:** Ubuntu Server and Kali Linux both running inside VirtualBox
* **Network:** Use placeholders such as `<your_ip>` instead of fixed IP values for flexibility

## What This Repository Contains

This repository includes comprehensive documentation for:

* Snort configuration files and custom rules
* Splunk Universal Forwarder inputs and outputs
* Verified command lists used during installation
* Validation and troubleshooting procedures
* Dashboard-ready SPL queries

All technical steps have been validated in a working setup.

## Skills Demonstrated

* Intrusion Detection Systems
* Log forwarding and SIEM integration
* Linux server configuration
* Regex-based alert parsing
* Network security monitoring
* Dashboard and analytics creation

## How to Use This Repository

1. Begin with the **Installation Guide** to set up Snort and Splunk.
2. Follow the **Master Playbook** for exact commands used during deployment.
3. Review the **Architecture** file to understand the flow of data.
4. Use the **SPL Queries** file to build dashboards and validate alert ingestion.

## Status

This documentation reflects a fully working Snort–Splunk integration. Further enhancements such as dashboards, alert correlation, and attack simulations can be added based on requirements.
