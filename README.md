# Security Automation 

## Overview

This repository showcases the foundational cybersecurity automation task.  
All work was performed solely for educational and learning purposes as part of my Internship.

## Task : Security Audit Automation

### Description

Automates basic security auditing by:

- Scanning a target system for open ports
- Checking service versions for known vulnerabilities
- Detecting common misconfigurations (e.g., weak SSH settings, inactive firewalls)
- Generating a clear, human-readable audit report

### How It Works

- Uses Python’s socket and subprocess libraries to scan for open ports and gather system configuration details
- Utilizes the requests library to fetch service banners and version info
- Summarizes all findings in a Markdown or text report for easy review

### Features

- Cross-platform compatibility (Windows/Linux)
- Accurate version detection and robust parsing
- Actionable, readable Markdown reporting

### Challenges & Solutions

- **Cross-platform compatibility:** Added OS detection and fallback logic
- **Accurate version detection:** Improved banner parsing for multiple services
- **Report readability:** Used Markdown formatting for clarity


## Key Learnings

- Automation increases the speed and reliability of security assessments
- Building both defensive (auditing) tool deepened my understanding of network security
- Ethical boundaries and safeguards are essential when simulating attacks, even in a lab setting

### Usage

#### Security Audit Automation

Run the script with your target IP address or domain and specify the ports you want to scan. You can also set the output file for the report.

## How to Run

### Prerequisites

- Python 3.8 or higher
- Install required packages:
  - `requests`
  - `pyOpenSSL`

#### Security Audit Automation :
python security_audit.py --target <TARGET_IP_ADDRDESS> --ports 22 80 443 8080 --output my_audit.md

## Disclaimer

- Use these script only on systems you own or have explicit permission to test.
- Unauthorized scanning is illegal and unethical.

## Summary

These project gave me hands-on experience with Python for automating security checks and understanding attack techniques—skills that are vital in today’s cybersecurity landscape.

I completed these project solely for educational and learning purposes, undertaking them exclusively as part of my educational training.  

## Created by 
Korada Chaitanya  


## License:
This project is for educational purposes only.
