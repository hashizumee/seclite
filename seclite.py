#!/usr/bin/env python3
"""
SecLite - Lightweight Network Security Scanner
Automated vulnerability scanning tool with real-time alerting and reporting
"""

import nmap
import socket
import json
import datetime
import argparse
import sys
from typing import Dict, List, Any
from scapy.all import ARP, Ether, srp, IP, ICMP, sr1
import threading
import time

class SecLite:
    def __init__(self, target: str, output_file: str = None):
        self.target = target
        self.output_file = output_file or f"seclite_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        self.scanner = nmap.PortScanner()
        self.results = {
            'scan_info': {
                'target': target,
                'timestamp': datetime.datetime.now().isoformat(),
                'scanner': 'SecLite v1.0'
            },
            'vulnerabilities': [],
            'open_ports': [],
            'services': [],
            'alerts': []
        }
        
    def banner(self):
        """Display SecLite banner"""
        banner_text = """
╔═══════════════════════════════════════════════════╗
║                                                   ║
║   ███████╗███████╗ ██████╗██╗     ██╗████████╗███████╗
║   ██╔════╝██╔════╝██╔════╝██║     ██║╚══██╔══╝██╔════╝
║   ███████╗█████╗  ██║     ██║     ██║   ██║   █████╗  
║   ╚════██║██╔══╝  ██║     ██║     ██║   ██║   ██╔══╝  
║   ███████║███████╗╚██████╗███████╗██║   ██║   ███████╗
║   ╚══════╝╚══════╝ ╚═════╝╚══════╝╚═╝   ╚═╝   ╚══════╝
║                                                   ║
║        Network Security Scanner v1.0              ║
║        Automated Vulnerability Detection          ║
╚═══════════════════════════════════════════════════╝
        """
        print(banner_text)
        
    def alert(self, severity: str, message: str):
        """Real-time alerting system"""
        alert_colors = {
            'CRITICAL': '\033[91m',  # Red
            'HIGH': '\033[93m',      # Yellow
            'MEDIUM': '\033[94m',    # Blue
            'LOW': '\033[92m',       # Green
            'INFO': '\033[96m'       # Cyan
        }
        reset_color = '\033[0m'
        
        timestamp = datetime.datetime.now().strftime('%H:%M:%S')
        color = alert_colors.get(severity, reset_color)
        
        alert_msg = f"[{timestamp}] {color}[{severity}]{reset_color} {message}"
        print(alert_msg)
        
        self.results['alerts'].append({
            'timestamp': timestamp,
            'severity': severity,
            'message': message
        })
        
    def scan_network_hosts(self, network_range: str = None):
        """Discover active hosts on the network"""
        if not network_range:
            network_range = self.target
            
        self.alert('INFO', f'Scanning network range: {network_range}')
        
        try:
            # ARP scan for host discovery
            arp_request = ARP(pdst=network_range)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
            
            hosts = []
            for sent, received in answered_list:
                hosts.append({'ip': received.psrc, 'mac': received.hwsrc})
                self.alert('INFO', f'Host discovered: {received.psrc} ({received.hwsrc})')
                
            return hosts
        except Exception as e:
            self.alert('HIGH', f'Network scan error: {str(e)}')
            return []
            
    def port_scan(self, ports: str = '1-1000'):
        """Comprehensive port scanning"""
        self.alert('INFO', f'Starting port scan on {self.target}')
        
        try:
            self.scanner.scan(self.target, ports, arguments='-sV -sC -O --script vuln')
            
            for host in self.scanner.all_hosts():
                for proto in self.scanner[host].all_protocols():
                    ports_list = self.scanner[host][proto].keys()
                    
                    for port in ports_list:
                        port_info = self.scanner[host][proto][port]
                        state = port_info['state']
                        service = port_info.get('name', 'unknown')
                        version = port_info.get('version', 'unknown')
                        
                        if state == 'open':
                            severity = self.assess_port_risk(port, service)
                            self.alert(severity, f'Open port: {port}/{proto} - {service} {version}')
                            
                            self.results['open_ports'].append({
                                'port': port,
                                'protocol': proto,
                                'state': state,
                                'service': service,
                                'version': version,
                                'risk': severity
                            })
                            
        except Exception as e:
            self.alert('CRITICAL', f'Port scan failed: {str(e)}')
            
    def assess_port_risk(self, port: int, service: str) -> str:
        """Assess risk level for open ports"""
        high_risk_ports = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            135: 'RPC', 139: 'NetBIOS', 445: 'SMB', 
            3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
            1433: 'MSSQL', 27017: 'MongoDB'
        }
        
        if port in high_risk_ports:
            return 'HIGH'
        elif port < 1024:
            return 'MEDIUM'
        else:
            return 'LOW'
            
    def vulnerability_scan(self):
        """Detect common vulnerabilities"""
        self.alert('INFO', 'Starting vulnerability assessment')
        
        vulns = []
        
        # Check for common vulnerabilities
        if self.scanner.all_hosts():
            for host in self.scanner.all_hosts():
                # Check for outdated services
                for proto in self.scanner[host].all_protocols():
                    for port in self.scanner[host][proto].keys():
                        service_info = self.scanner[host][proto][port]
                        
                        # Example vulnerability checks
                        if service_info.get('name') == 'ftp' and service_info.get('state') == 'open':
                            vuln = {
                                'type': 'Insecure Service',
                                'severity': 'HIGH',
                                'port': port,
                                'description': 'FTP service detected - unencrypted transmission',
                                'recommendation': 'Consider using SFTP or FTPS instead'
                            }
                            vulns.append(vuln)
                            self.alert('HIGH', f'Vulnerability: Insecure FTP on port {port}')
                            
                        if service_info.get('name') == 'telnet':
                            vuln = {
                                'type': 'Critical Security Issue',
                                'severity': 'CRITICAL',
                                'port': port,
                                'description': 'Telnet service - unencrypted remote access',
                                'recommendation': 'Disable Telnet and use SSH instead'
                            }
                            vulns.append(vuln)
                            self.alert('CRITICAL', f'Vulnerability: Telnet on port {port}')
                            
        self.results['vulnerabilities'] = vulns
        
    def service_enumeration(self):
        """Enumerate services and versions"""
        self.alert('INFO', 'Enumerating services')
        
        services = []
        if self.scanner.all_hosts():
            for host in self.scanner.all_hosts():
                for proto in self.scanner[host].all_protocols():
                    for port in self.scanner[host][proto].keys():
                        service = self.scanner[host][proto][port]
                        services.append({
                            'port': port,
                            'service': service.get('name', 'unknown'),
                            'product': service.get('product', 'unknown'),
                            'version': service.get('version', 'unknown'),
                            'extrainfo': service.get('extrainfo', '')
                        })
                        
        self.results['services'] = services
        
    def generate_report(self):
        """Generate comprehensive JSON report"""
        self.alert('INFO', f'Generating report: {self.output_file}')
        
        self.results['scan_info']['end_time'] = datetime.datetime.now().isoformat()
        
        with open(self.output_file, 'w') as f:
            json.dump(self.results, f, indent=4)
            
        # Print summary
        print("\n" + "="*60)
        print("SCAN SUMMARY")
        print("="*60)
        print(f"Target: {self.target}")
        print(f"Open Ports: {len(self.results['open_ports'])}")
        print(f"Services Detected: {len(self.results['services'])}")
        print(f"Vulnerabilities: {len(self.results['vulnerabilities'])}")
        print(f"Alerts Generated: {len(self.results['alerts'])}")
        print(f"\nReport saved to: {self.output_file}")
        print("="*60 + "\n")
        
    def run_full_scan(self):
        """Execute complete security scan"""
        self.banner()
        
        print(f"\n[*] Starting SecLite scan on {self.target}\n")
        
        # Port scanning
        self.port_scan()
        
        # Service enumeration
        self.service_enumeration()
        
        # Vulnerability detection
        self.vulnerability_scan()
        
        # Generate report
        self.generate_report()
        
        self.alert('INFO', 'Scan completed successfully')

def main():
    parser = argparse.ArgumentParser(
        description='SecLite - Network Security Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python seclite.py -t 192.168.1.1
  python seclite.py -t 192.168.1.0/24 -p 1-65535
  python seclite.py -t scanme.nmap.org -o report.json
        """
    )
    
    parser.add_argument('-t', '--target', required=True, help='Target IP or network range')
    parser.add_argument('-p', '--ports', default='1-1000', help='Port range (default: 1-1000)')
    parser.add_argument('-o', '--output', help='Output file name')
    
    args = parser.parse_args()
    
    # Initialize scanner
    scanner = SecLite(args.target, args.output)
    
    # Run scan
    scanner.run_full_scan()

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error: {str(e)}")
        sys.exit(1)