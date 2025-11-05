import asyncio
import aiohttp
import socket
from contextlib import closing

class PortScanAgent:
    def __init__(self):
        self.name = "Port Scanning Agent"
        self.description = "Performs port scanning and service discovery"
        self.common_ports = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            993: "IMAPS",
            995: "POP3S",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL"
        }
    
    async def investigate(self, target, ports=None):
        """Perform port scanning on target"""
        print(f"🔍 Port Agent investigating: {target}")
        
        if ports is None:
            ports = list(self.common_ports.keys())[:10]  # Limit for demo
        
        results = {
            'port_agent': {
                'target': target,
                'open_ports': [],
                'scan_summary': {}
            }
        }
        
        try:
            open_ports = await self.scan_ports(target, ports)
            results['port_agent']['open_ports'] = open_ports
            results['port_agent']['scan_summary'] = {
                'total_scanned': len(ports),
                'open_ports_found': len(open_ports),
                'success_rate': f"{(len(open_ports)/len(ports))*100:.1f}%"
            }
            
        except Exception as e:
            results['port_agent']['error'] = str(e)
        
        return results
    
    async def scan_ports(self, target, ports):
        """Async port scanner for common ports"""
        open_ports = []
        
        # Resolve hostname to IP if needed
        try:
            ip = await self.resolve_hostname(target)
        except:
            ip = target
        
        tasks = [self.check_port(ip, port) for port in ports]
        results = await asyncio.gather(*tasks)
        
        for port, is_open in zip(ports, results):
            if is_open:
                service = self.common_ports.get(port, "Unknown")
                open_ports.append({
                    'port': port,
                    'service': service,
                    'state': 'open'
                })
                print(f"    ✅ Port {port} ({service}) - OPEN")
            else:
                print(f"    ❌ Port {port} - Closed")
        
        return open_ports
    
    async def resolve_hostname(self, hostname):
        """Resolve hostname to IP address"""
        try:
            return socket.gethostbyname(hostname)
        except socket.gaierror:
            return hostname
    
    async def check_port(self, ip, port, timeout=2):
        """Check if a port is open"""
        try:
            with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((ip, port))
                return result == 0
        except:
            return False
    
    def analyze_results(self, results):
        """AI-powered analysis of port scan results"""
        analysis = []
        
        port_data = results.get('port_agent', {})
        open_ports = port_data.get('open_ports', [])
        
        for port_info in open_ports:
            port = port_info['port']
            service = port_info['service']
            
            if port in [21, 22, 23]:
                analysis.append(f"⚠️  Port {port} ({service}) - Remote access service, check for weak authentication")
            elif port in [80, 443]:
                analysis.append(f"🌐 Port {port} ({service}) - Web service detected, potential for web application testing")
            elif port == 25:
                analysis.append(f"📧 Port {port} ({service}) - Mail transfer agent, check for open relay")
            elif port == 53:
                analysis.append(f"🔍 Port {port} ({service}) - DNS service, potential for DNS enumeration")
        
        if not open_ports:
            analysis.append("🔒 No open ports found - target appears well-secured")
        
        return analysis