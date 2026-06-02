# SOC Log Parser & Threat Intelligence Enrichment Tool

## Overview

The SOC Log Parser & Threat Intelligence Enrichment Tool is a Python-based security monitoring project designed to simulate the workflow of a Security Operations Center (SOC) analyst.

The tool ingests firewall and DNS logs, applies detection logic to identify suspicious activity, enriches indicators of compromise (IOCs) using the VirusTotal API, and generates structured JSON alerts for further investigation.

This project demonstrates how log analysis, threat detection, and threat intelligence enrichment can be automated using Python.

---

## Features

### Firewall Log Analysis

The parser reads firewall logs and extracts:

* Timestamp
* Source IP address
* Destination IP address
* Protocol
* Destination port
* Action performed

Example:

2025-05-01 12:00:00 SRC=192.168.1.10 DST=8.8.8.8 PROTO=TCP DPT=443 ACTION=ALLOW

---

### Beaconing Detection

One common behavior of malware is Command-and-Control (C2) beaconing.

The tool identifies systems that repeatedly communicate with the same external IP address.

Detection Logic:

* Count all source-to-destination connections
* If the same pair appears more than the configured threshold
* Generate a high-severity alert

Example:

192.168.1.50 → 45.33.32.156 repeated 10 times

Possible interpretation:

* Malware callback activity
* Remote access trojan communication
* Automated beaconing behavior

---

### DNS Log Analysis

The parser processes DNS logs and extracts:

* Timestamp
* Client IP
* Domain queried
* Query type

Example:

2025-05-01 12:05:00 CLIENT=192.168.1.10 QUERY=google.com TYPE=A

---

### DNS Tunneling Detection

Attackers often use DNS for covert data exfiltration.

A common indicator is an unusually long subdomain containing encoded data.

Example:

YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo.malicious.com

Detection Logic:

* Extract the subdomain
* Measure its length
* Flag queries exceeding the configured threshold

This helps identify:

* DNS tunneling
* Data exfiltration attempts
* Malware communication channels

---

### VirusTotal Threat Intelligence Enrichment

After detecting suspicious activity, the tool automatically queries VirusTotal.

Supported IOC Types:

* IP addresses
* Domains

For each IOC, the tool retrieves:

* Malicious detections
* Suspicious detections
* Harmless detections
* Undetected results

This provides additional context for analysts and helps prioritize investigations.

---

## Project Workflow

Step 1:
Read firewall and DNS logs

↓

Step 2:
Parse and normalize log data

↓

Step 3:
Run detection rules

* Beaconing detection
* DNS tunneling detection

↓

Step 4:
Extract suspicious indicators

↓

Step 5:
Enrich indicators using VirusTotal

↓

Step 6:
Generate structured alerts

↓

Step 7:
Export results to JSON

---

## Project Structure

soc-log-parser/

├── parser.py

├── logs/

│   ├── firewall.log

│   └── dns.log

├── output/

│   └── alerts.json

├── .env

└── README.md

---

## Configuration

The project uses environment variables to securely store API credentials.

Create a `.env` file:

VIRUSTOTAL_API_KEY=your_api_key_here

---

## Detection Thresholds

Current detection settings:

Beaconing Threshold:

* 5 repeated connections

DNS Tunneling Threshold:

* 40 character subdomain length

These values can be adjusted depending on the environment being monitored.

---

## Output Example

The tool generates alerts in JSON format.

Example:

{
"alert_type": "BEACONING",
"severity": "HIGH",
"src_ip": "192.168.1.50",
"dst_ip": "45.33.32.156",
"connections": 10,
"description": "192.168.1.50 connected to 45.33.32.156 10 times - possible C2 beaconing",
"virustotal": {
"malicious": 5,
"suspicious": 2,
"harmless": 60,
"undetected": 10
}
}

---

## Skills Demonstrated

This project showcases practical SOC and cybersecurity skills including:

* Log Analysis
* Threat Detection Engineering
* IOC Extraction
* Threat Intelligence Integration
* Security Automation
* Python Scripting
* JSON Data Handling
* API Integration
* Detection Rule Development
* Security Monitoring

---

## Future Improvements

Potential enhancements include:

* Additional detection rules
* GeoIP enrichment
* MITRE ATT&CK mapping
* SIEM integration
* Email alerting
* Dashboard visualization
* Machine learning anomaly detection
* Multi-threaded VirusTotal lookups
* CSV and HTML reporting

---

## Educational Purpose

This project was developed as a cybersecurity portfolio project to demonstrate Security Operations Center (SOC) analyst skills and the automation of common blue-team workflows using Python.
