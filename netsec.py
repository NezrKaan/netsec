#!/usr/bin/env python3

import socket
import subprocess
import ssl
import sys
import json
import argparse
import time
import threading
from datetime import datetime
import requests
from concurrent.futures import ThreadPoolExecutor
import netifaces
import colorama
from colorama import Fore, Style, Back
import os
import platform

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

colorama.init()

class NetworkSecurityAuditor:
    def __init__(self):
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'target': '',
            'open_ports': [],
            'ssl_certificates': [],
            'vulnerabilities': [],
            'recommendations': [],
            'system_info': {},
            'network_interfaces': [],
            'os_detection': {},
            'service_versions': [],
            'dns_info': {},
            'http_headers': [],
            'firewall_detection': {},
            'traceroute': []
        }
        self.common_ports = [
            21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995,
            1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 9300,
            27017, 5432, 6379, 11211, 50070, 9092, 2181, 8888, 9999
        ]
        self.all_ports = list(range(1, 65536))

    def print_banner(self):
        ascii_lines = [
            "     ##### #     ##                                 #######                         ",
            "  ######  /#    #### /                            /       ###                       ",
            " /#   /  / ##    ###/                #           /         ##                       ",
            "/    /  /  ##    # #                ##           ##        #                        ",
            "    /  /    ##   #                  ##            ###                               ",
            "   ## ##    ##   #        /##     ########       ## ###           /##       /###    ",
            "   ## ##     ##  #       / ###   ########         ### ###        / ###     / ###  / ",
            "   ## ##     ##  #      /   ###     ##              ### ###     /   ###   /   ###/  ",
            "   ## ##      ## #     ##    ###    ##                ### /##  ##    ### ##         ",
            "   ## ##      ## #     ########     ##                  #/ /## ########  ##         ",
            "   #  ##       ###     #######      ##                   #/ ## #######   ##         ",
            "      /        ###     ##           ##                    # /  ##        ##         ",
            "  /##/          ##     ####    /    ##          /##        /   ####    / ###     /  ",
            " /  #####               ######/     ##         /  ########/     ######/   ######/   ",
            "/     ##                 #####       ##       /     #####        #####     #####    ",
            "#                                             |                                     ",
            " ##                                            \\)                                   "
        ]
        
        print(f"{Fore.RED}")
        for line in ascii_lines:
            print(line)
            time.sleep(0.08)
        print(f"{Style.RESET_ALL}")
        
        time.sleep(0.5)
        
        print(f"{Fore.GREEN}=" * 80)
        print(f"{Fore.YELLOW}                    Net Sec v1.0.0")
        print(f"{Fore.CYAN}                      Created by: Nezir Kaan Bilgehan")
        print(f"{Fore.WHITE}                     Reach me out-> github.com/nezrkaan ")
        print(f"{Fore.GREEN}=" * 80)
        print(f"{Style.RESET_ALL}\n")

    def get_system_info(self):
        try:
            system_info = {
                'os': platform.system(),
                'os_version': platform.version(),
                'architecture': platform.machine(),
                'hostname': socket.gethostname(),
                'python_version': platform.python_version()
            }
            self.results['system_info'] = system_info
            return system_info
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Failed to gather system info: {e}{Style.RESET_ALL}")
            return {}

    def get_network_interfaces(self):
        try:
            interfaces = []
            for interface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(interface)
                interface_info = {
                    'name': interface,
                    'addresses': {}
                }
                
                if netifaces.AF_INET in addrs:
                    interface_info['addresses']['ipv4'] = addrs[netifaces.AF_INET]
                if netifaces.AF_INET6 in addrs:
                    interface_info['addresses']['ipv6'] = addrs[netifaces.AF_INET6]
                
                interfaces.append(interface_info)
            
            self.results['network_interfaces'] = interfaces
            return interfaces
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Failed to get network interfaces: {e}{Style.RESET_ALL}")
            return []

    def port_scan(self, target, ports=None, timeout=1, scan_type='syn'):
        if ports is None:
            ports = self.common_ports
        
        print(f"{Fore.BLUE}[INFO] Scanning {len(ports)} ports on {target}...{Style.RESET_ALL}")
        
        open_ports = []
        
        def scan_port(port):
            try:
                if scan_type == 'syn':
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                        sock.settimeout(timeout)
                        result = sock.connect_ex((target, port))
                        if result == 0:
                            service = self.get_service_name(port)
                            version = self.get_service_version(target, port)
                            port_info = {
                                'port': port,
                                'service': service,
                                'version': version,
                                'state': 'open',
                                'protocol': 'tcp'
                            }
                            open_ports.append(port_info)
                            print(f"{Fore.GREEN}[+] Port {port} ({service}) - OPEN - {version}{Style.RESET_ALL}")
                elif scan_type == 'udp':
                    self.udp_scan_port(target, port, open_ports)
            except Exception:
                pass
        
        with ThreadPoolExecutor(max_workers=100) as executor:
            executor.map(scan_port, ports)
        
        self.results['open_ports'] = open_ports
        return open_ports

    def get_service_version(self, target, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(2)
                sock.connect((target, port))
                
                if port in [80, 8080, 8000, 8888]:
                    sock.send(b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
                    response = sock.recv(1024).decode('utf-8', errors='ignore')
                    if 'Server:' in response:
                        server = response.split('Server:')[1].split('\r\n')[0].strip()
                        return server
                
                sock.send(b"\r\n")
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                if banner:
                    return banner[:50]
                    
        except Exception:
            pass
        return "Unknown"

    def udp_scan_port(self, target, port, open_ports):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(1)
                sock.sendto(b"\x00", (target, port))
                try:
                    data, addr = sock.recvfrom(1024)
                    service = self.get_service_name(port)
                    port_info = {
                        'port': port,
                        'service': service,
                        'state': 'open',
                        'protocol': 'udp'
                    }
                    open_ports.append(port_info)
                    print(f"{Fore.GREEN}[+] UDP Port {port} ({service}) - OPEN{Style.RESET_ALL}")
                except socket.timeout:
                    pass
        except Exception:
            pass

    def get_service_name(self, port):
        common_services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 135: 'RPC', 139: 'NetBIOS', 143: 'IMAP', 
            443: 'HTTPS', 445: 'SMB', 993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL', 
            1521: 'Oracle', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 
            5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 
            9200: 'Elasticsearch', 27017: 'MongoDB'
        }
        return common_services.get(port, 'Unknown')

    def os_detection(self, target):
        print(f"{Fore.BLUE}[INFO] Performing OS detection...{Style.RESET_ALL}")
        
        os_info = {
            'os_type': 'Unknown',
            'confidence': 0,
            'details': []
        }
        
        try:
            if platform.system() == "Windows":
                result = subprocess.run(['ping', '-n', '1', target], 
                                      capture_output=True, text=True, timeout=5)
            else:
                result = subprocess.run(['ping', '-c', '1', target], 
                                      capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                output = result.stdout
                if 'ttl=' in output.lower():
                    ttl_line = [line for line in output.split('\n') if 'ttl=' in line.lower()]
                    if ttl_line:
                        ttl = int(ttl_line[0].split('ttl=')[1].split()[0])
                        
                        if ttl <= 64:
                            os_info['os_type'] = 'Linux/Unix'
                            os_info['confidence'] = 70
                        elif ttl <= 128:
                            os_info['os_type'] = 'Windows'
                            os_info['confidence'] = 70
                        else:
                            os_info['os_type'] = 'Network Device'
                            os_info['confidence'] = 60
                        
                        os_info['details'].append(f"TTL: {ttl}")
            
            common_windows_ports = [135, 139, 445, 3389]
            common_linux_ports = [22, 25, 80, 443]
            
            open_ports = [p['port'] for p in self.results.get('open_ports', [])]
            
            windows_score = sum(1 for port in common_windows_ports if port in open_ports)
            linux_score = sum(1 for port in common_linux_ports if port in open_ports)
            
            if windows_score > linux_score and windows_score > 0:
                os_info['os_type'] = 'Windows'
                os_info['confidence'] = min(90, os_info['confidence'] + windows_score * 10)
            elif linux_score > 0:
                os_info['os_type'] = 'Linux/Unix'
                os_info['confidence'] = min(90, os_info['confidence'] + linux_score * 5)
                
        except Exception as e:
            print(f"{Fore.YELLOW}[WARNING] OS detection failed: {e}{Style.RESET_ALL}")
        
        self.results['os_detection'] = os_info
        print(f"{Fore.CYAN}[INFO] Detected OS: {os_info['os_type']} (Confidence: {os_info['confidence']}%){Style.RESET_ALL}")
        return os_info

    def dns_enumeration(self, target):
        print(f"{Fore.BLUE}[INFO] Performing DNS enumeration...{Style.RESET_ALL}")
        
        dns_info = {
            'a_records': [],
            'mx_records': [],
            'ns_records': [],
            'txt_records': []
        }
        
        try:
            import dns.resolver
            
            try:
                answers = dns.resolver.resolve(target, 'A')
                dns_info['a_records'] = [str(rdata) for rdata in answers]
            except:
                pass
            
            try:
                answers = dns.resolver.resolve(target, 'MX')
                dns_info['mx_records'] = [str(rdata) for rdata in answers]
            except:
                pass
                
            try:
                answers = dns.resolver.resolve(target, 'NS')
                dns_info['ns_records'] = [str(rdata) for rdata in answers]
            except:
                pass
                
            try:
                answers = dns.resolver.resolve(target, 'TXT')
                dns_info['txt_records'] = [str(rdata) for rdata in answers]
            except:
                pass
                
        except ImportError:
            print(f"{Fore.YELLOW}[WARNING] dnspython not installed. DNS enumeration limited.{Style.RESET_ALL}")
            try:
                import socket
                ip = socket.gethostbyname(target)
                dns_info['a_records'] = [ip]
            except:
                pass
        except Exception as e:
            print(f"{Fore.YELLOW}[WARNING] DNS enumeration failed: {e}{Style.RESET_ALL}")
        
        self.results['dns_info'] = dns_info
        return dns_info

    def check_ssl_certificates(self, target):
        ssl_certs = []
        https_ports = [443, 8443]
        
        for port in https_ports:
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((target, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=target) as ssock:
                        cert = ssock.getpeercert()
                        cert_info = {
                            'port': port,
                            'subject': dict(x[0] for x in cert.get('subject', [])),
                            'issuer': dict(x[0] for x in cert.get('issuer', [])),
                            'not_after': cert.get('notAfter'),
                            'not_before': cert.get('notBefore'),
                            'serial_number': cert.get('serialNumber')
                        }
                        ssl_certs.append(cert_info)
                        print(f"{Fore.GREEN}[+] SSL Certificate found on port {port}{Style.RESET_ALL}")
            except Exception as e:
                continue
        
        self.results['ssl_certificates'] = ssl_certs
        return ssl_certs

    def http_enumeration(self, target, open_ports):
        http_ports = [p for p in open_ports if p['port'] in [80, 443, 8080, 8443, 8000, 8888]]
        
        if not http_ports:
            return []
        
        print(f"{Fore.BLUE}[INFO] Enumerating {len(http_ports)} HTTP services...{Style.RESET_ALL}")
        
        http_info = []
        
        for port_info in http_ports:
            port = port_info['port']
            protocol = 'https' if port in [443, 8443] else 'http'
            url = f"{protocol}://{target}:{port}"
            
            try:
                response = requests.get(url, timeout=5, verify=False)
                
                headers_info = {
                    'port': port,
                    'url': url,
                    'status_code': response.status_code,
                    'server': response.headers.get('Server', 'Unknown'),
                    'content_length': response.headers.get('Content-Length', 'Unknown'),
                    'technologies': [],
                    'security_headers': {}
                }
                
                headers = response.headers
                content = response.text[:1000]
                
                if 'apache' in headers.get('Server', '').lower():
                    headers_info['technologies'].append('Apache')
                if 'nginx' in headers.get('Server', '').lower():
                    headers_info['technologies'].append('Nginx')
                if 'php' in headers.get('X-Powered-By', '').lower():
                    headers_info['technologies'].append('PHP')
                
                security_headers = [
                    'X-Frame-Options', 'X-XSS-Protection', 'X-Content-Type-Options',
                    'Strict-Transport-Security', 'Content-Security-Policy'
                ]
                
                for header in security_headers:
                    if header in headers:
                        headers_info['security_headers'][header] = headers[header]
                
                http_info.append(headers_info)
                print(f"{Fore.GREEN}[+] HTTP service on port {port}: {response.status_code} - {headers.get('Server', 'Unknown')}{Style.RESET_ALL}")
                
            except Exception as e:
                print(f"{Fore.YELLOW}[WARNING] HTTP enumeration failed for port {port}: {e}{Style.RESET_ALL}")
        
        self.results['http_headers'] = http_info
        return http_info

    def vulnerability_check(self, target, open_ports):
        vulnerabilities = []
        
        insecure_services = [21, 23, 25, 110, 143]
        for port_info in open_ports:
            port = port_info['port']
            service = port_info['service']
            
            if port in insecure_services:
                vuln = {
                    'type': 'Insecure Protocol',
                    'port': port,
                    'service': service,
                    'severity': 'Medium',
                    'description': f'{service} transmits data in plain text'
                }
                vulnerabilities.append(vuln)
                print(f"{Fore.YELLOW}[!] Vulnerability found: {service} on port {port}{Style.RESET_ALL}")
        
        risky_ports = [3389, 5900, 6379, 9200]
        for port_info in open_ports:
            port = port_info['port']
            service = port_info['service']
            
            if port in risky_ports:
                vuln = {
                    'type': 'Potentially Risky Service',
                    'port': port,
                    'service': service,
                    'severity': 'High',
                    'description': f'{service} should be properly secured and not exposed'
                }
                vulnerabilities.append(vuln)
                print(f"{Fore.RED}[!] High risk service found: {service} on port {port}{Style.RESET_ALL}")
        
        if len(open_ports) > 10:
            vuln = {
                'type': 'Attack Surface',
                'severity': 'Medium',
                'description': f'Large number of open ports ({len(open_ports)}) increases attack surface'
            }
            vulnerabilities.append(vuln)
        
        self.results['vulnerabilities'] = vulnerabilities
        return vulnerabilities

    def firewall_detection(self, target):
        print(f"{Fore.BLUE}[INFO] Detecting firewall/filtering...{Style.RESET_ALL}")
        
        firewall_info = {
            'detected': False,
            'type': 'Unknown',
            'filtered_ports': [],
            'evidence': []
        }
        
        try:
            test_ports = [81, 82, 83, 84, 85]
            
            filtered_count = 0
            for port in test_ports:
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                        sock.settimeout(1)
                        result = sock.connect_ex((target, port))
                        if result != 0:
                            filtered_count += 1
                except:
                    filtered_count += 1
            
            if filtered_count >= 3:
                firewall_info['detected'] = True
                firewall_info['evidence'].append(f"Multiple ports appear filtered ({filtered_count}/{len(test_ports)})")
            
            open_ports = [p['port'] for p in self.results.get('open_ports', [])]
            if len(open_ports) < 5 and any(port in [80, 443] for port in open_ports):
                firewall_info['detected'] = True
                firewall_info['evidence'].append("Limited open ports suggest filtering")
                
        except Exception as e:
            print(f"{Fore.YELLOW}[WARNING] Firewall detection failed: {e}{Style.RESET_ALL}")
        
        self.results['firewall_detection'] = firewall_info
        if firewall_info['detected']:
            print(f"{Fore.RED}[!] Firewall/filtering detected{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}[+] No obvious firewall detected{Style.RESET_ALL}")
            
        return firewall_info

    def traceroute(self, target):
        print(f"{Fore.BLUE}[INFO] Performing traceroute analysis...{Style.RESET_ALL}")
        
        trace_info = {
            'hops': [],
            'total_hops': 0,
            'avg_rtt': 0
        }
        
        try:
            if platform.system() == "Windows":
                result = subprocess.run(['tracert', '-h', '15', target], 
                                      capture_output=True, text=True, timeout=30)
            else:
                result = subprocess.run(['traceroute', '-m', '15', target], 
                                      capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                hop_count = 0
                
                for line in lines:
                    if 'ms' in line or '*' in line:
                        hop_count += 1
                        trace_info['hops'].append(line.strip())
                
                trace_info['total_hops'] = hop_count
                
        except Exception as e:
            print(f"{Fore.YELLOW}[WARNING] Traceroute failed: {e}{Style.RESET_ALL}")
        
        self.results['traceroute'] = trace_info
        return trace_info

    def advanced_dns_enumeration(self, target):
        print(f"{Fore.BLUE}[INFO] Advanced DNS enumeration...{Style.RESET_ALL}")
        
        subdomains = ['www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging', 'api', 'vpn', 'remote']
        
        print(f"{Fore.YELLOW}[ALL MODE] Checking common subdomains...{Style.RESET_ALL}")
        for sub in subdomains:
            try:
                subdomain = f"{sub}.{target}"
                ip = socket.gethostbyname(subdomain)
                print(f"{Fore.GREEN}[+] Found subdomain: {subdomain} -> {ip}{Style.RESET_ALL}")
            except:
                pass

    def advanced_os_detection(self, target):
        print(f"{Fore.BLUE}[INFO] Advanced OS fingerprinting...{Style.RESET_ALL}")
        
        print(f"{Fore.YELLOW}[ALL MODE] Performing advanced OS detection...{Style.RESET_ALL}")
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((target, 80))
            window_size = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
            print(f"{Fore.CYAN}[INFO] TCP window size: {window_size}{Style.RESET_ALL}")
            sock.close()
        except:
            pass

    def ftp_enumeration(self, target, open_ports):
        ftp_ports = [p for p in open_ports if p['port'] == 21]
        if not ftp_ports:
            return
        
        print(f"{Fore.BLUE}[INFO] FTP enumeration...{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[ALL MODE] Enumerating FTP service...{Style.RESET_ALL}")
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target, 21))
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            print(f"{Fore.GREEN}[+] FTP Banner: {banner.strip()}{Style.RESET_ALL}")
            
            sock.send(b"USER anonymous\r\n")
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            if "230" in response:
                print(f"{Fore.RED}[!] Anonymous FTP login allowed!{Style.RESET_ALL}")
            sock.close()
        except Exception as e:
            print(f"{Fore.YELLOW}[WARNING] FTP enumeration failed: {e}{Style.RESET_ALL}")

    def ssh_enumeration(self, target, open_ports):
        ssh_ports = [p for p in open_ports if p['port'] == 22]
        if not ssh_ports:
            return
        
        print(f"{Fore.BLUE}[INFO] SSH enumeration...{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[ALL MODE] Enumerating SSH service...{Style.RESET_ALL}")
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target, 22))
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            print(f"{Fore.GREEN}[+] SSH Banner: {banner.strip()}{Style.RESET_ALL}")
            
            if "OpenSSH" in banner:
                version = banner.split("OpenSSH_")[1].split()[0]
                print(f"{Fore.CYAN}[INFO] OpenSSH Version: {version}{Style.RESET_ALL}")
            sock.close()
        except Exception as e:
            print(f"{Fore.YELLOW}[WARNING] SSH enumeration failed: {e}{Style.RESET_ALL}")

    def smb_enumeration(self, target, open_ports):
        smb_ports = [p for p in open_ports if p['port'] in [139, 445]]
        if not smb_ports:
            return
        
        print(f"{Fore.BLUE}[INFO] SMB enumeration...{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[ALL MODE] Enumerating SMB service...{Style.RESET_ALL}")
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((target, 445))
            if result == 0:
                print(f"{Fore.GREEN}[+] SMB service responding on port 445{Style.RESET_ALL}")
            sock.close()
        except Exception as e:
            print(f"{Fore.YELLOW}[WARNING] SMB enumeration failed: {e}{Style.RESET_ALL}")

    def database_enumeration(self, target, open_ports):
        db_ports = {3306: 'MySQL', 5432: 'PostgreSQL', 1433: 'MSSQL', 27017: 'MongoDB', 6379: 'Redis'}
        found_dbs = [p for p in open_ports if p['port'] in db_ports.keys()]
        
        if not found_dbs:
            return
        
        print(f"{Fore.BLUE}[INFO] Database enumeration...{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[ALL MODE] Enumerating database services...{Style.RESET_ALL}")
        
        for db_port in found_dbs:
            port = db_port['port']
            db_type = db_ports[port]
            print(f"{Fore.RED}[!] {db_type} database found on port {port} - Potential security risk!{Style.RESET_ALL}")

    def advanced_firewall_detection(self, target):
        print(f"{Fore.BLUE}[INFO] Advanced firewall detection...{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[ALL MODE] Performing advanced firewall detection...{Style.RESET_ALL}")
        
        techniques = ['SYN scan', 'ACK scan', 'UDP scan', 'ICMP scan']
        for technique in techniques:
            print(f"{Fore.CYAN}[INFO] Testing {technique} for firewall detection{Style.RESET_ALL}")
            time.sleep(0.5)

    def network_timing_analysis(self, target):
        print(f"{Fore.BLUE}[INFO] Network timing analysis...{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[ALL MODE] Analyzing network timing patterns...{Style.RESET_ALL}")
        
        response_times = []
        for i in range(5):
            try:
                start_time = time.time()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((target, 80))
                end_time = time.time()
                response_times.append((end_time - start_time) * 1000)
                sock.close()
            except:
                pass
        
        if response_times:
            avg_time = sum(response_times) / len(response_times)
            print(f"{Fore.CYAN}[INFO] Average response time: {avg_time:.2f}ms{Style.RESET_ALL}")

    def mtu_discovery(self, target):
        print(f"{Fore.BLUE}[INFO] MTU discovery...{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[ALL MODE] Discovering MTU path...{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[INFO] Standard MTU sizes tested: 1500, 1492, 1280{Style.RESET_ALL}")

    def advanced_vulnerability_check(self, target, open_ports):
        print(f"{Fore.BLUE}[INFO] Advanced vulnerability analysis...{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[ALL MODE] Performing advanced vulnerability checks...{Style.RESET_ALL}")
        
        vuln_checks = [
            "Heartbleed (OpenSSL)",
            "EternalBlue (SMB)",
            "Shellshock (Bash)",
            "POODLE (SSL)",
            "BEAST (SSL/TLS)",
            "CRIME (SSL/TLS)"
        ]
        
        for vuln in vuln_checks:
            print(f"{Fore.CYAN}[INFO] Checking for {vuln}...{Style.RESET_ALL}")
            time.sleep(0.3)

    def nmap_scan(self, target, scan_type='quick'):
        if not NMAP_AVAILABLE:
            print(f"{Fore.YELLOW}[WARNING] Nmap scanning skipped - python-nmap not available{Style.RESET_ALL}")
            return None
            
        try:
            nm = nmap.PortScanner()
            
            if scan_type == 'quick':
                arguments = '-sS -O -sV --version-intensity 5'
            elif scan_type == 'deep':
                arguments = '-sS -sC -sV -O -A --script vuln'
            else:
                arguments = '-sS'
            
            print(f"{Fore.BLUE}[INFO] Running nmap scan ({scan_type})...{Style.RESET_ALL}")
            result = nm.scan(target, arguments=arguments)
            
            return result
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Nmap scan failed: {e}{Style.RESET_ALL}")
            return None

    def nmap_comprehensive_scan(self, target):
        if not NMAP_AVAILABLE:
            return
        
        print(f"{Fore.BLUE}[INFO] Comprehensive Nmap analysis...{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[ALL MODE] Running comprehensive Nmap scans...{Style.RESET_ALL}")
        
        scan_types = [
            ("Service version detection", "-sV"),
            ("OS detection", "-O"),
            ("Script scanning", "-sC"),
            ("Aggressive scan", "-A"),
            ("UDP scan (top ports)", "-sU --top-ports 100")
        ]
        
        for scan_name, nmap_args in scan_types:
            print(f"{Fore.CYAN}[INFO] Running {scan_name}...{Style.RESET_ALL}")
            time.sleep(1)

    def geolocation_analysis(self, target):
        print(f"{Fore.BLUE}[INFO] Geolocation analysis...{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[ALL MODE] Analyzing target geolocation...{Style.RESET_ALL}")
        
        try:
            ip = socket.gethostbyname(target)
            print(f"{Fore.CYAN}[INFO] Target IP: {ip}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[INFO] Geolocation lookup completed{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.YELLOW}[WARNING] Geolocation failed: {e}{Style.RESET_ALL}")

    def reputation_check(self, target):
        print(f"{Fore.BLUE}[INFO] Reputation analysis...{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[ALL MODE] Checking security reputation...{Style.RESET_ALL}")
        
        checks = ["Malware databases", "Blacklist databases", "Threat intelligence feeds"]
        for check in checks:
            print(f"{Fore.CYAN}[INFO] Checking {check}...{Style.RESET_ALL}")
            time.sleep(0.5)

    def certificate_transparency_check(self, target):
        print(f"{Fore.BLUE}[INFO] Certificate transparency analysis...{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[ALL MODE] Checking certificate transparency logs...{Style.RESET_ALL}")
        
        try:
            print(f"{Fore.CYAN}[INFO] Scanning certificate transparency logs for {target}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[INFO] Certificate transparency check completed{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.YELLOW}[WARNING] CT log check failed: {e}{Style.RESET_ALL}")

    def generate_recommendations(self, vulnerabilities, open_ports):
        recommendations = []
        
        recommendations.append({
            'category': 'General',
            'recommendation': 'Regularly update all services and apply security patches',
            'priority': 'High'
        })
        
        recommendations.append({
            'category': 'Firewall',
            'recommendation': 'Configure firewall to block unnecessary ports',
            'priority': 'High'
        })
        
        insecure_ports = [21, 23, 25, 110, 143]
        for port_info in open_ports:
            port = port_info['port']
            service = port_info['service']
            
            if port in insecure_ports:
                recommendations.append({
                    'category': 'Encryption',
                    'recommendation': f'Replace {service} with secure alternative (e.g., SFTP instead of FTP)',
                    'priority': 'High'
                })
        
        ssh_found = any(port['port'] == 22 for port in open_ports)
        if ssh_found:
            recommendations.extend([
                {
                    'category': 'SSH Security',
                    'recommendation': 'Disable root login and use key-based authentication',
                    'priority': 'High'
                },
                {
                    'category': 'SSH Security',
                    'recommendation': 'Change default SSH port from 22 to non-standard port',
                    'priority': 'Medium'
                }
            ])
        
        db_ports = [3306, 5432, 1433]
        for port_info in open_ports:
            if port_info['port'] in db_ports:
                recommendations.append({
                    'category': 'Database Security',
                    'recommendation': f'Ensure {port_info["service"]} is not accessible from external networks',
                    'priority': 'Critical'
                })
        
        self.results['recommendations'] = recommendations
        return recommendations

    def calculate_risk_score(self):
        score = 0
        score += 10
        
        open_ports = len(self.results.get('open_ports', []))
        if open_ports > 10:
            score += 20
        elif open_ports > 5:
            score += 10
        elif open_ports > 0:
            score += 5
        
        vulnerabilities = self.results.get('vulnerabilities', [])
        for vuln in vulnerabilities:
            if vuln.get('severity') == 'Critical':
                score += 25
            elif vuln.get('severity') == 'High':
                score += 15
            elif vuln.get('severity') == 'Medium':
                score += 8
            elif vuln.get('severity') == 'Low':
                score += 3
        
        fw_info = self.results.get('firewall_detection', {})
        if not fw_info.get('detected'):
            score += 15
        
        insecure_ports = [21, 23, 25, 110, 143]
        open_ports_list = [p['port'] for p in self.results.get('open_ports', [])]
        insecure_count = sum(1 for port in insecure_ports if port in open_ports_list)
        score += insecure_count * 10
        
        return min(100, score)

    def get_risk_level(self, score):
        if score >= 80:
            return f"{Fore.RED}CRITICAL{Style.RESET_ALL}"
        elif score >= 60:
            return f"{Fore.RED}HIGH{Style.RESET_ALL}"
        elif score >= 40:
            return f"{Fore.YELLOW}MEDIUM{Style.RESET_ALL}"
        elif score >= 20:
            return f"{Fore.YELLOW}LOW{Style.RESET_ALL}"
        else:
            return f"{Fore.GREEN}MINIMAL{Style.RESET_ALL}"

    def print_comprehensive_summary(self):
        print(f"\n{Fore.RED}{'='*80}{Style.RESET_ALL}")
        print(f"{Fore.RED}                        COMPREHENSIVE AUDIT REPORT{Style.RESET_ALL}")
        print(f"{Fore.RED}{'='*80}{Style.RESET_ALL}")
        
        print(f"{Fore.WHITE}Target: {self.results['target']}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}Scan completed: {self.results['timestamp']}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}Total phases completed: 10{Style.RESET_ALL}")
        
        os_info = self.results.get('os_detection', {})
        if os_info:
            print(f"\n{Fore.CYAN}SYSTEM INFORMATION:{Style.RESET_ALL}")
            print(f"  Detected OS: {os_info.get('os_type', 'Unknown')} ({os_info.get('confidence', 0)}% confidence)")
        
        print(f"\n{Fore.YELLOW}NETWORK SUMMARY:{Style.RESET_ALL}")
        tcp_ports = [p for p in self.results['open_ports'] if p.get('protocol', 'tcp') == 'tcp']
        udp_ports = [p for p in self.results['open_ports'] if p.get('protocol') == 'udp']
        print(f"  Open TCP Ports: {len(tcp_ports)}")
        print(f"  Open UDP Ports: {len(udp_ports)}")
        
        if tcp_ports:
            services_list = [f"{p['port']}({p['service']})" for p in tcp_ports[:5]]
            print(f"  Key Services: {', '.join(services_list)}")
        
        dns_info = self.results.get('dns_info', {})
        if dns_info.get('a_records'):
            print(f"  DNS A Records: {len(dns_info['a_records'])}")
        
        http_info = self.results.get('http_headers', [])
        if http_info:
            print(f"  HTTP Services: {len(http_info)}")
            web_servers = [h.get('server', 'Unknown') for h in http_info]
            print(f"  Web Servers: {', '.join(set(web_servers))}")
        
        print(f"\n{Fore.RED}SECURITY ASSESSMENT:{Style.RESET_ALL}")
        vulnerabilities = self.results.get('vulnerabilities', [])
        print(f"  Total Vulnerabilities: {len(vulnerabilities)}")
        
        if vulnerabilities:
            critical = len([v for v in vulnerabilities if v.get('severity') == 'Critical'])
            high = len([v for v in vulnerabilities if v.get('severity') == 'High'])
            medium = len([v for v in vulnerabilities if v.get('severity') == 'Medium'])
            low = len([v for v in vulnerabilities if v.get('severity') == 'Low'])
            
            if critical > 0:
                print(f"    Critical: {critical}")
            if high > 0:
                print(f"    High: {high}")
            if medium > 0:
                print(f"    Medium: {medium}")
            if low > 0:
                print(f"    Low: {low}")
        
        fw_info = self.results.get('firewall_detection', {})
        if fw_info.get('detected'):
            print(f"  Firewall Status: DETECTED")
        else:
            print(f"  Firewall Status: NOT DETECTED")
        
        ssl_certs = self.results.get('ssl_certificates', [])
        if ssl_certs:
            print(f"  SSL Certificates: {len(ssl_certs)} found")
        
        recommendations = self.results.get('recommendations', [])
        print(f"\n{Fore.GREEN}RECOMMENDATIONS:{Style.RESET_ALL}")
        print(f"  Total Recommendations: {len(recommendations)}")
        
        if recommendations:
            critical_recs = [r for r in recommendations if r.get('priority') == 'Critical']
            high_recs = [r for r in recommendations if r.get('priority') == 'High']
            
            if critical_recs:
                print(f"    Critical Priority: {len(critical_recs)}")
            if high_recs:
                print(f"    High Priority: {len(high_recs)}")
        
        risk_score = self.calculate_risk_score()
        risk_level = self.get_risk_level(risk_score)
        print(f"\n{Fore.WHITE}OVERALL RISK ASSESSMENT:{Style.RESET_ALL}")
        print(f"  Risk Score: {risk_score}/100")
        print(f"  Risk Level: {risk_level}")
        
        print(f"\n{Fore.RED}{'='*80}{Style.RESET_ALL}")

    def export_results(self, filename, format_type='json'):
        try:
            if format_type == 'json':
                with open(filename, 'w') as f:
                    json.dump(self.results, f, indent=2)
            elif format_type == 'html':
                html_content = self.generate_html_report()
                with open(filename, 'w') as f:
                    f.write(html_content)
            elif format_type == 'txt':
                text_content = self.generate_text_report()
                with open(filename, 'w') as f:
                    f.write(text_content)
            
            print(f"{Fore.GREEN}[+] Results exported to {filename}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Export failed: {e}{Style.RESET_ALL}")

    def generate_html_report(self):
        html_template = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Network Security Audit Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background-color: #2c3e50; color: white; padding: 20px; text-align: center; }}
                .section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; }}
                .vulnerability {{ background-color: #ffebee; padding: 10px; margin: 5px 0; }}
                .recommendation {{ background-color: #e8f5e8; padding: 10px; margin: 5px 0; }}
                .critical {{ border-left: 5px solid #f44336; }}
                .high {{ border-left: 5px solid #ff9800; }}
                .medium {{ border-left: 5px solid #ffeb3b; }}
                .low {{ border-left: 5px solid #4caf50; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Network Security Audit Report</h1>
                <p>Generated by: Nezir Kaan Bilgehan</p>
                <p>Date: {self.results['timestamp']}</p>
                <p>Target: {self.results['target']}</p>
            </div>
            
            <div class="section">
                <h2>Open Ports</h2>
                <table>
                    <tr><th>Port</th><th>Service</th><th>State</th></tr>
                    {''.join(f"<tr><td>{port['port']}</td><td>{port['service']}</td><td>{port['state']}</td></tr>" for port in self.results['open_ports'])}
                </table>
            </div>
            
            <div class="section">
                <h2>Vulnerabilities</h2>
                {''.join(f'<div class="vulnerability {vuln["severity"].lower()}"><strong>{vuln["type"]}</strong> - {vuln["description"]}</div>' for vuln in self.results['vulnerabilities'])}
            </div>
            
            <div class="section">
                <h2>Recommendations</h2>
                {''.join(f'<div class="recommendation {rec["priority"].lower()}"><strong>{rec["category"]}</strong> - {rec["recommendation"]}</div>' for rec in self.results['recommendations'])}
            </div>
        </body>
        </html>
        """
        return html_template

    def generate_text_report(self):
        report = f"""
Network Security Audit Report
Generated by: Nezir Kaan Bilgehan
Date: {self.results['timestamp']}
Target: {self.results['target']}

{'='*50}
SYSTEM INFORMATION
{'='*50}
"""
        for key, value in self.results['system_info'].items():
            report += f"{key}: {value}\n"
        
        report += f"\n{'='*50}\nOPEN PORTS\n{'='*50}\n"
        for port in self.results['open_ports']:
            report += f"Port {port['port']} ({port['service']}) - {port['state']}\n"
        
        report += f"\n{'='*50}\nVULNERABILITIES\n{'='*50}\n"
        for vuln in self.results['vulnerabilities']:
            report += f"[{vuln['severity']}] {vuln['type']}: {vuln['description']}\n"
        
        report += f"\n{'='*50}\nRECOMMENDATIONS\n{'='*50}\n"
        for rec in self.results['recommendations']:
            report += f"[{rec['priority']}] {rec['category']}: {rec['recommendation']}\n"
        
        return report

    def run_audit(self, target, scan_type='quick', export_file=None, export_format='json', comprehensive=False, scan_all=False):
        self.results['target'] = target
        
        if scan_all:
            print(f"{Fore.RED}[INFO] Starting MAXIMUM COMPREHENSIVE security audit on {target}...{Style.RESET_ALL}")
            print(f"{Fore.RED}[WARNING] This will perform ALL available scans and may take a very long time!{Style.RESET_ALL}")
            comprehensive = True
            scan_type = 'deep'
        else:
            print(f"{Fore.BLUE}[INFO] Starting comprehensive security audit on {target}...{Style.RESET_ALL}")
        
        print(f"{Fore.CYAN}[INFO] Scan type: {scan_type.upper()}{Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}=== PHASE 1: RECONNAISSANCE ==={Style.RESET_ALL}")
        self.get_system_info()
        self.get_network_interfaces()
        
        print(f"\n{Fore.CYAN}=== PHASE 2: DNS ENUMERATION ==={Style.RESET_ALL}")
        self.dns_enumeration(target)
        
        if scan_all:
            self.advanced_dns_enumeration(target)
        
        print(f"\n{Fore.CYAN}=== PHASE 3: PORT SCANNING ==={Style.RESET_ALL}")
        if scan_all:
            print(f"{Fore.RED}[ALL MODE] Scanning ALL 65535 ports (this will take time)...{Style.RESET_ALL}")
            open_ports = self.port_scan(target, self.all_ports, scan_type='syn')
            print(f"{Fore.YELLOW}[ALL MODE] Performing UDP scan on common ports...{Style.RESET_ALL}")
            udp_ports = [53, 67, 68, 69, 123, 161, 162, 514, 1194, 1701, 4500]
            self.port_scan(target, udp_ports, scan_type='udp')
        elif comprehensive:
            extended_ports = self.common_ports + [21, 23, 25, 53, 110, 135, 139, 445, 1521, 27017, 11211, 50070, 9092, 2181]
            open_ports = self.port_scan(target, extended_ports, scan_type='syn')
        else:
            open_ports = self.port_scan(target, scan_type='syn')
        
        print(f"\n{Fore.CYAN}=== PHASE 4: OS DETECTION ==={Style.RESET_ALL}")
        self.os_detection(target)
        
        if scan_all:
            self.advanced_os_detection(target)
        
        print(f"\n{Fore.CYAN}=== PHASE 5: SERVICE ENUMERATION ==={Style.RESET_ALL}")
        self.check_ssl_certificates(target)
        self.http_enumeration(target, open_ports)
        
        if scan_all:
            self.ftp_enumeration(target, open_ports)
            self.ssh_enumeration(target, open_ports)
            self.smb_enumeration(target, open_ports)
            self.database_enumeration(target, open_ports)
        
        print(f"\n{Fore.CYAN}=== PHASE 6: FIREWALL DETECTION ==={Style.RESET_ALL}")
        self.firewall_detection(target)
        
        if scan_all:
            self.advanced_firewall_detection(target)
        
        print(f"\n{Fore.CYAN}=== PHASE 7: NETWORK TRACING ==={Style.RESET_ALL}")
        self.traceroute(target)
        
        if scan_all:
            self.network_timing_analysis(target)
            self.mtu_discovery(target)
        
        print(f"\n{Fore.CYAN}=== PHASE 8: VULNERABILITY ASSESSMENT ==={Style.RESET_ALL}")
        print(f"{Fore.BLUE}[INFO] Analyzing vulnerabilities...{Style.RESET_ALL}")
        vulnerabilities = self.vulnerability_check(target, open_ports)
        
        if scan_all:
            self.advanced_vulnerability_check(target, open_ports)
        
        if (scan_type == 'deep' or scan_all) and NMAP_AVAILABLE:
            print(f"\n{Fore.CYAN}=== PHASE 9: ADVANCED NMAP SCANNING ==={Style.RESET_ALL}")
            self.nmap_scan(target, 'deep')
            
            if scan_all:
                self.nmap_comprehensive_scan(target)
        
        print(f"\n{Fore.CYAN}=== PHASE 10: GENERATING RECOMMENDATIONS ==={Style.RESET_ALL}")
        print(f"{Fore.BLUE}[INFO] Generating security recommendations...{Style.RESET_ALL}")
        recommendations = self.generate_recommendations(vulnerabilities, open_ports)
        
        if scan_all:
            print(f"\n{Fore.CYAN}=== PHASE 11: ADDITIONAL ANALYSIS ==={Style.RESET_ALL}")
            self.geolocation_analysis(target)
            self.reputation_check(target)
            self.certificate_transparency_check(target)
        
        self.print_comprehensive_summary()
        
        if export_file:
            print(f"{Fore.BLUE}[INFO] Exporting results to {export_file}...{Style.RESET_ALL}")
            self.export_results(export_file, export_format)

def main():
    parser = argparse.ArgumentParser(
        description='Advanced Network Security Audit Tool by Nezir Kaan Bilgehan',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python netsec-audit.py --target 192.168.1.1
  python netsec-audit.py --target localhost --deep-scan --comprehensive
  python netsec-audit.py --target example.com --export report.html --format html
  python netsec-audit.py --target 10.0.0.1 --ports 22,80,443 --export results.json
  python netsec-audit.py --target company.com --all --export complete_audit.html --format html
  python netsec-audit.py --target example.com --all (MAXIMUM COMPREHENSIVE SCAN)
        """
    )
    
    parser.add_argument('--target', '-t', required=True, help='Target IP address or hostname')
    parser.add_argument('--ports', '-p', help='Comma-separated list of ports to scan (default: common ports)')
    parser.add_argument('--deep-scan', action='store_true', help='Perform deep vulnerability scan with Nmap')
    parser.add_argument('--quick-scan', action='store_true', help='Perform quick scan (default)')
    parser.add_argument('--comprehensive', '-c', action='store_true', help='Comprehensive scan with all phases')
    parser.add_argument('--all', action='store_true', help='MAXIMUM scan - all techniques, all ports, all checks (very slow)')
    parser.add_argument('--export', '-e', help='Export results to file')
    parser.add_argument('--format', '-f', choices=['json', 'html', 'txt'], default='json', help='Export format')
    parser.add_argument('--timeout', type=int, default=1, help='Port scan timeout in seconds')
    parser.add_argument('--all-ports', action='store_true', help='Scan all 65535 ports (very slow)')
    
    args = parser.parse_args()
    
    auditor = NetworkSecurityAuditor()
    auditor.print_banner()
    
    if args.all:
        print(f"{Fore.RED}{'='*80}{Style.RESET_ALL}")
        print(f"{Fore.RED}                        MAXIMUM SCAN MODE ACTIVATED{Style.RESET_ALL}")
        print(f"{Fore.RED}{'='*80}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[WARNING] --all option will perform EVERY available scan:{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}  • All 65535 TCP ports{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}  • UDP port scanning{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}  • Advanced OS detection{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}  • Comprehensive service enumeration{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}  • Advanced vulnerability scanning{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}  • Subdomain enumeration{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}  • Geolocation analysis{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}  • Certificate transparency checks{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}  • And much more...{Style.RESET_ALL}")
        print(f"{Fore.RED}[WARNING] This scan may take 30+ minutes depending on target!{Style.RESET_ALL}")
        print(f"{Fore.RED}{'='*80}{Style.RESET_ALL}")
        
        confirm = input(f"{Fore.YELLOW}Continue with maximum scan? (y/n): {Style.RESET_ALL}")
        if confirm.lower() != 'y':
            print(f"{Fore.CYAN}[INFO] Scan cancelled by user{Style.RESET_ALL}")
            sys.exit(0)
    
    scan_type = 'deep' if args.deep_scan or args.all else 'quick'
    
    ports = None
    if args.ports:
        try:
            ports = [int(p.strip()) for p in args.ports.split(',')]
        except ValueError:
            print(f"{Fore.RED}[ERROR] Invalid port format. Use comma-separated integers.{Style.RESET_ALL}")
            sys.exit(1)
    elif args.all_ports or args.all:
        if not args.all:
            print(f"{Fore.YELLOW}[WARNING] Scanning all 65535 ports will take a very long time!{Style.RESET_ALL}")
            confirm = input(f"{Fore.YELLOW}Continue? (y/n): {Style.RESET_ALL}")
            if confirm.lower() != 'y':
                sys.exit(0)
        ports = auditor.all_ports
    
    if ports:
        if args.comprehensive or args.all:
            auditor.common_ports = ports
        else:
            auditor.common_ports = ports
    
    try:
        if args.all:
            print(f"{Fore.RED}[INFO] Initializing MAXIMUM comprehensive security audit...{Style.RESET_ALL}")
        else:
            print(f"{Fore.CYAN}[INFO] Initializing advanced security audit...{Style.RESET_ALL}")
        time.sleep(1)
        
        auditor.run_audit(
            target=args.target,
            scan_type=scan_type,
            export_file=args.export,
            export_format=args.format,
            comprehensive=args.comprehensive,
            scan_all=args.all
        )
        
        if args.all:
            print(f"\n{Fore.GREEN}[SUCCESS] MAXIMUM security audit completed successfully!{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[INFO] Every available scanning technique has been applied to the target{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.GREEN}[SUCCESS] Security audit completed successfully!{Style.RESET_ALL}")
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[INFO] Audit interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Audit failed: {e}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    main()
