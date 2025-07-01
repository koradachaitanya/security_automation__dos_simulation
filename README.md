# Security Automation & Ethical DoS Simulation

## Overview

This repository showcases two foundational cybersecurity automation tasks, completed during my internship at LEARNCORP.  
All work was performed solely for educational and learning purposes as part of my training.

## Task 1: Security Audit Automation

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

## Task 2: Ethical DoS Attack Simulation

### Description

Simulates a Denial of Service (DoS) attack in a controlled, ethical environment to illustrate resource exhaustion and monitoring strategies.

### How It Works

- Uses the requests library to send a configurable number of HTTP requests to a specified test server
- Includes a delay parameter to control the rate of requests and prevent accidental harm
- Implements safety prompts and configuration checks to ensure ethical use in isolated environments

### Features

- Configurable request count and delay
- Built-in safeguards and explicit user confirmation
- Designed for test environments only

### Challenges & Solutions

- **Preventing misuse:** Added explicit user confirmation and rate limiting
- **Testing safely:** Used only test servers and low request counts

## Key Learnings

- Automation increases the speed and reliability of security assessments
- Building both defensive (auditing) and offensive (DoS simulation) tools deepened my understanding of network security
- Ethical boundaries and safeguards are essential when simulating attacks, even in a lab setting

### Usage

#### Security Audit Automation

Run the script with your target IP address or domain and specify the ports you want to scan. You can also set the output file for the report.

#### Ethical DoS Attack Simulation

Run the script with the target URL, number of requests to send, and (optionally) the delay between requests.

## How to Run

### Prerequisites

- Python 3.8 or higher
- Install required packages:
  - `requests`
  - `pyOpenSSL`



## Disclaimer

- Use these scripts only on systems you own or have explicit permission to test.
- Unauthorized scanning or attack simulation is illegal and unethical.

## Summary

These projects gave me hands-on experience with Python for both automating security checks and understanding attack techniques—skills that are vital in today’s cybersecurity landscape.

I completed these projects solely for educational and learning purposes, undertaking them exclusively as part of my educational training.  
As this is the last week of my internship with LEARNCORP, I am grateful for the valuable experience and knowledge I have gained during this journey.

Created by Korada Chaitanya  
Intern, LEARNCORP

## License:
This project is for educational purposes only.
