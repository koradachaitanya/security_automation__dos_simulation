#!/usr/bin/env python3
"""
Security Audit Automation Script
Performs port scanning, service version checks, vulnerability detection, and security flaw identification
"""

import argparse
import socket
import requests
import subprocess
import os
import ssl
import datetime
from OpenSSL import crypto
import re
import sys

# Vulnerability database (in-memory example)
VULNERABILITY_DB = {
    'Apache': {
        'vulnerable_versions': ['2.4.41', '2.4.39', '2.4.38', '2.4.37'],
        'cves': ['CVE-2021-42013', 'CVE-2021-41773']
    },
    'nginx': {
        'vulnerable_versions': ['1.16.0', '1.15.12', '1.14.2'],
        'cves': ['CVE-2021-23017', 'CVE-2020-12440']
    },
    'OpenSSH': {
        'vulnerable_versions': ['8.4p1', '8.3p1', '7.9p1'],
        'cves': ['CVE-2021-41617', 'CVE-2020-14145']
    },
    'Microsoft-IIS': {
        'vulnerable_versions': ['10.0.15063', '8.5'],
        'cves': ['CVE-2017-7269', 'CVE-2015-1635']
    }
}

def check_open_ports(host, ports):
    """Scan for open ports using TCP connect method"""
    open_ports = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                result = sock.connect_ex((host, port))
                if result == 0:
                    try:
                        service_name = socket.getservbyport(port, 'tcp')
                    except OSError:
                        service_name = "unknown"
                    open_ports.append((port, service_name))
        except Exception as e:
            print(f"[!] Error scanning port {port}: {str(e)}", file=sys.stderr)
    return open_ports

def get_ssh_banner(host, port=22, timeout=3):
    """Retrieve SSH service banner"""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            banner = sock.recv(1024).decode(errors='ignore').strip()
            return banner.split('\n')[0] if banner else "SSH (no banner)"
    except Exception:
        return "SSH (no response)"

def check_service_versions(host, open_ports):
    """Detect service versions for open ports"""
    service_versions = {}
    for port, service_name in open_ports:
        try:
            # HTTP/HTTPS services
            if port in [80, 443, 8080, 8443]:
                protocol = 'https' if port in [443, 8443] else 'http'
                url = f"{protocol}://{host}:{port}"
                response = requests.get(url, timeout=3, verify=False)
                server_header = response.headers.get('Server', 'Unknown')
                service_versions[port] = server_header
            
            # SSH service
            elif port == 22:
                service_versions[port] = get_ssh_banner(host, port)
            
            # Other services
            else:
                try:
                    service_versions[port] = f"{service_name} (no version detection)"
                except:
                    service_versions[port] = "Unknown service"
        except requests.RequestException:
            service_versions[port] = 'No HTTP response'
        except Exception as e:
            service_versions[port] = f'Error: {str(e)}'
    return service_versions

def check_vulnerabilities(service_versions):
    """Check detected versions against vulnerability database"""
    vulnerabilities = []
    for port, version in service_versions.items():
        for service, data in VULNERABILITY_DB.items():
            if service in version:
                for vuln_version in data['vulnerable_versions']:
                    if vuln_version in version:
                        cve_list = ', '.join(data['cves'])
                        vulnerabilities.append(
                            f"Port {port}: Vulnerable {service} version ({version}) - {cve_list}"
                        )
    return vulnerabilities

def check_security_flaws(host, open_ports):
    """Identify security misconfigurations"""
    flaws = []
    
    # SSH Configuration Checks
    try:
        if any(port == 22 for port, _ in open_ports):
            if os.path.exists('/etc/ssh/sshd_config'):
                with open('/etc/ssh/sshd_config', 'r') as f:
                    sshd_config = f.read()
                    if 'PermitRootLogin yes' in sshd_config:
                        flaws.append('SSH root login enabled (CWE-250)')
                    if 'PasswordAuthentication yes' in sshd_config:
                        flaws.append('SSH password authentication enabled (CWE-798)')
            else:
                flaws.append('SSH configuration file not found')
    except Exception as e:
        flaws.append(f'SSH config check failed: {str(e)}')
    
    # Firewall Status Check
    try:
        if os.name == 'posix':
            result = subprocess.run(['ufw', 'status'], capture_output=True, text=True)
            if 'inactive' in result.stdout.lower():
                flaws.append('Firewall is inactive')
        elif os.name == 'nt':
            result = subprocess.run(
                ['netsh', 'advfirewall', 'show', 'allprofiles'], 
                capture_output=True, 
                text=True
            )
            if 'OFF' in result.stdout:
                flaws.append('Windows Firewall is inactive')
    except Exception as e:
        flaws.append(f'Firewall check failed: {str(e)}')
    
    # SSL Certificate Checks
    for port, _ in open_ports:
        if port in [443, 8443]:
            try:
                cert = ssl.get_server_certificate((host, port))
                x509 = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
                expiry_bytes = x509.get_notAfter()
                
                if expiry_bytes:
                    expiry_date = expiry_bytes.decode('utf-8')
                    expiry = datetime.datetime.strptime(expiry_date, '%Y%m%d%H%M%SZ')
                    if expiry < datetime.datetime.utcnow():
                        flaws.append(f"Expired SSL certificate on port {port}")
            except Exception as e:
                flaws.append(f"SSL check failed on port {port}: {str(e)}")
    
    return flaws

def generate_report(target, open_ports, service_versions, vulnerabilities, flaws):
    """Generate Markdown format security report"""
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # Format open ports section
    ports_section = "✅ No open ports detected\n" if not open_ports else "\n".join(
        f"- 🔓 Port `{port}` ({service})" for port, service in open_ports
    )
    
    # Format service versions
    versions_section = "\n".join(
        f"- Port `{port}`: {version}" for port, version in service_versions.items()
    ) if service_versions else "No service versions detected"
    
    # Format vulnerabilities
    vuln_section = "✅ No vulnerabilities detected\n" if not vulnerabilities else "\n".join(
        f"- 🔥 {vuln}" for vuln in vulnerabilities
    )
    
    # Format security flaws
    flaws_section = "✅ No security flaws detected\n" if not flaws else "\n".join(
        f"- ⚠️ {flaw}" for flaw in flaws
    )
    
    # Generate recommendations based on findings
    recommendations = []
    if any("Vulnerable" in v for v in vulnerabilities):
        recommendations.append("1. Patch vulnerable services immediately")
    if any("SSH" in f for f in flaws):
        recommendations.append("2. Harden SSH configuration (disable root login, use key auth)")
    if any("Firewall" in f for f in flaws):
        recommendations.append("3. Enable and configure firewall")
    if any("SSL" in f for f in flaws):
        recommendations.append("4. Renew expired SSL certificates")
    
    rec_section = "\n".join(recommendations) if recommendations else "No specific recommendations"
    
    # Compile full report
    report = f"""
## 🔒 Security Audit Report
**Target:** `{target}`  
**Scan Date:** {timestamp}  
**Generated By:** Security Audit Script v2.0

### 📡 Open Ports
{ports_section}

### 🔍 Service Versions
{versions_section}

### 🚨 Identified Vulnerabilities
{vuln_section}

### ⚠️ Security Flaws
{flaws_section}

### ✅ Recommendations
{rec_section}

---
Report generated automatically with security-audit-tool.py
"""
    return report

def main():
    parser = argparse.ArgumentParser(description='Automated Security Audit Tool')
    parser.add_argument('--target', required=True, help='Target host or IP address')
    parser.add_argument('--ports', nargs='+', type=int, 
                        default=[20, 21, 22, 23, 25, 53, 69, 80, 123, 143, 161, 169, 179, 443, 500, 587, 8080, 8081, 3306, 3389],
                        help='Ports to scan (space separated)')
    parser.add_argument('--output', default='security_audit_report.md',
                        help='Output report filename')
    args = parser.parse_args()

    print(f"[*] Starting security audit for {args.target}...")
    
    # 1. Scan for open ports
    print("[*] Scanning for open ports...")
    open_ports = check_open_ports(args.target, args.ports)
    
    # 2. Check service versions
    print("[*] Checking service versions...")
    service_versions = check_service_versions(args.target, open_ports)
    
    # 3. Check for vulnerabilities
    print("[*] Checking for known vulnerabilities...")
    vulnerabilities = check_vulnerabilities(service_versions)
    
    # 4. Identify security flaws
    print("[*] Identifying security flaws...")
    flaws = check_security_flaws(args.target, open_ports)
    
    # 5. Generate report
    print("[*] Generating security report...")
    report = generate_report(
        args.target,
        open_ports,
        service_versions,
        vulnerabilities,
        flaws
    )
    
    # Save report to file
    with open(args.output, 'w', encoding='utf-8') as f:
        f.write(report)
    
    
    print(f"[+] Audit complete! Report saved to {args.output}")
    print(f"\nSummary: {len(open_ports)} open ports | {len(vulnerabilities)} vulnerabilities | {len(flaws)} flaws")

if __name__ == '__main__':
    main()
