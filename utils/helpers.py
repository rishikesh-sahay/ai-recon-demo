import re
import socket
import sys
import platform
from datetime import datetime

def validate_domain(domain):
    """Validate domain name format"""
    if not domain:
        return False
    
    # Remove any accidental whitespace
    domain = domain.strip()
    
    # Basic domain regex pattern
    domain_regex = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$'
    
    # Also allow localhost for testing
    if domain.lower() in ['localhost', 'local']:
        return True
        
    return re.match(domain_regex, domain) is not None

def validate_ip(ip):
    """Validate IP address format"""
    if not ip:
        return False
        
    ip = ip.strip()
    
    # Allow localhost
    if ip.lower() in ['localhost', '127.0.0.1', '::1']:
        return True
    
    # IPv4 validation
    try:
        socket.inet_pton(socket.AF_INET, ip)
        return True
    except socket.error:
        pass
    
    # IPv6 validation
    try:
        socket.inet_pton(socket.AF_INET6, ip)
        return True
    except socket.error:
        pass
    
    return False

def extract_domain_from_url(input_str):
    """Extract domain from URL input"""
    if not input_str:
        return ""
        
    # Remove any accidental whitespace
    input_str = input_str.strip()
    
    # If it's already a clean domain or IP, return as is
    if validate_domain(input_str) or validate_ip(input_str):
        return input_str
    
    # Remove protocol
    domain = re.sub(r'^https?://', '', input_str, flags=re.IGNORECASE)
    
    # Remove port numbers
    domain = re.sub(r':\d+', '', domain)
    
    # Remove path and query parameters
    domain = re.sub(r'[/?#].*$', '', domain)
    
    # Remove www prefix
    domain = re.sub(r'^www\.', '', domain, flags=re.IGNORECASE)
    
    # Final cleanup
    domain = domain.strip()
    
    return domain

def sanitize_input(input_str):
    """Sanitize user input to prevent injection attacks"""
    if not input_str:
        return ""
    
    # Remove potentially dangerous characters
    sanitized = re.sub(r'[^\w\.\-:]', '', input_str)
    
    # Limit length
    if len(sanitized) > 255:
        sanitized = sanitized[:255]
    
    return sanitized

def check_python_version():
    """Check if Python version is compatible"""
    version = sys.version_info
    return version.major >= 3 and version.minor >= 8

def get_system_info():
    """Get system information for troubleshooting"""
    return {
        'platform': platform.system(),
        'platform_release': platform.release(),
        'platform_version': platform.version(),
        'architecture': platform.architecture(),
        'processor': platform.processor(),
        'python_version': platform.python_version()
    }

def print_banner():
    """Print a cool banner for the demo"""
    banner = """
    ╔═══════════════════════════════════════════════════════════╗
    ║                  AI RECONNAISSANCE AGENT                 ║
    ║               Penetration Testing Demo                   ║
    ║                                                           ║
    ║           🤖 Multi-Agent Reconnaissance System           ║
    ║           🔍 DNS Enumeration • Port Scanning             ║
    ║           🧠 AI-Powered Analysis & Insights              ║
    ║                                                           ║
    ║              For Educational Purposes Only               ║
    ║               Use Only in Controlled Environments        ║
    ╚═══════════════════════════════════════════════════════════╝
    """
    print(banner)

def print_section_header(title):
    """Print a formatted section header"""
    print(f"\n{'='*60}")
    print(f" {title}")
    print(f"{'='*60}")

def print_success(message):
    """Print a success message"""
    print(f"✅ {message}")

def print_warning(message):
    """Print a warning message"""
    print(f"⚠️  {message}")

def print_error(message):
    """Print an error message"""
    print(f"❌ {message}")

def print_info(message):
    """Print an info message"""
    print(f"💡 {message}")

def format_timestamp():
    """Get current timestamp in readable format"""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def calculate_duration(start_time, end_time):
    """Calculate duration between two timestamps"""
    duration = end_time - start_time
    if duration < 60:
        return f"{duration:.2f} seconds"
    elif duration < 3600:
        return f"{duration/60:.2f} minutes"
    else:
        return f"{duration/3600:.2f} hours"

def format_file_size(size_bytes):
    """Format file size in human-readable format"""
    if size_bytes == 0:
        return "0 bytes"
    
    size_names = ["bytes", "KB", "MB", "GB"]
    i = 0
    while size_bytes >= 1024 and i < len(size_names) - 1:
        size_bytes /= 1024.0
        i += 1
    
    return f"{size_bytes:.2f} {size_names[i]}"

def validate_target_input(target):
    """Comprehensive target input validation"""
    if not target:
        return False, "Target cannot be empty"
    
    # Sanitize input
    clean_target = sanitize_input(target)
    if not clean_target:
        return False, "Invalid characters in target"
    
    # Extract domain from URL if needed
    final_target = extract_domain_from_url(clean_target)
    
    # Validate the final target
    if validate_domain(final_target) or validate_ip(final_target):
        return True, final_target
    else:
        return False, f"Invalid target format: {final_target}"

def check_network_connectivity(host="8.8.8.8", port=53, timeout=3):
    """Check if network connectivity is available"""
    try:
        socket.setdefaulttimeout(timeout)
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((host, port))
        return True
    except socket.error:
        return False

def get_common_ports(service_filter=None):
    """Get common ports for scanning"""
    common_ports = {
        # Web Services
        80: "HTTP",
        443: "HTTPS", 
        8080: "HTTP-ALT",
        8443: "HTTPS-ALT",
        3000: "Node.js",
        5000: "Flask",
        
        # Remote Access
        22: "SSH",
        23: "Telnet",
        3389: "RDP",
        5900: "VNC",
        
        # File Transfer
        21: "FTP",
        69: "TFTP",
        989: "FTPS-DATA",
        990: "FTPS",
        
        # Email
        25: "SMTP",
        110: "POP3",
        143: "IMAP",
        993: "IMAPS",
        995: "POP3S",
        
        # Database
        1433: "MSSQL",
        1521: "Oracle",
        3306: "MySQL",
        5432: "PostgreSQL",
        27017: "MongoDB",
        
        # DNS
        53: "DNS",
        
        # Other Services
        161: "SNMP",
        389: "LDAP",
        636: "LDAPS",
        873: "Rsync",
        2049: "NFS",
    }
    
    if service_filter:
        filtered_ports = {}
        for port, service in common_ports.items():
            if service_filter.lower() in service.lower():
                filtered_ports[port] = service
        return filtered_ports
    
    return common_ports

def format_dns_record(record_type, record_data):
    """Format DNS record for display"""
    if isinstance(record_data, list):
        return [f"{record_type}: {record}" for record in record_data]
    else:
        return [f"{record_type}: {record_data}"]

def analyze_dns_complexity(dns_records):
    """Analyze DNS complexity based on records"""
    complexity_score = 0
    insights = []
    
    # Check for multiple A records (load balancing)
    a_records = dns_records.get('A', [])
    if isinstance(a_records, list) and len(a_records) > 1:
        complexity_score += 2
        insights.append("Multiple A records detected - possible load balancing")
    
    # Check for IPv6 support
    aaaa_records = dns_records.get('AAAA', [])
    if aaaa_records and not "Not found" in str(aaaa_records):
        complexity_score += 1
        insights.append("IPv6 support detected")
    
    # Check for multiple MX records (email redundancy)
    mx_records = dns_records.get('MX', [])
    if isinstance(mx_records, list) and len(mx_records) > 1:
        complexity_score += 2
        insights.append("Multiple MX records - email redundancy configured")
    
    # Check for multiple NS records
    ns_records = dns_records.get('NS', [])
    if isinstance(ns_records, list) and len(ns_records) > 2:
        complexity_score += 1
        insights.append("Robust DNS infrastructure (multiple name servers)")
    
    # Check for TXT records (security features)
    txt_records = dns_records.get('TXT', [])
    if txt_records and isinstance(txt_records, list):
        complexity_score += len(txt_records) * 0.5
        insights.append(f"Multiple TXT records ({len(txt_records)}) - various configurations")
    
    # Determine complexity level
    if complexity_score >= 5:
        complexity_level = "High"
    elif complexity_score >= 3:
        complexity_level = "Medium"
    else:
        complexity_level = "Low"
    
    return {
        'score': complexity_score,
        'level': complexity_level,
        'insights': insights
    }

def generate_target_variations(domain):
    """Generate common target variations for testing"""
    variations = []
    
    if validate_domain(domain):
        variations.extend([
            domain,
            f"www.{domain}",
            f"mail.{domain}",
            f"ftp.{domain}",
            f"admin.{domain}",
            f"api.{domain}",
            f"test.{domain}",
            f"dev.{domain}",
            f"staging.{domain}",
            f"portal.{domain}"
        ])
    
    return variations

def print_usage_examples():
    """Print usage examples for students"""
    examples = """
    🎯 USAGE EXAMPLES:
    
    Basic Usage:
      python main.py
      > Enter target: example.com
    
    Direct Command Line:
      python main.py
      > Enter target: google.com
    
    Local Testing:
      python main.py  
      > Enter target: 127.0.0.1
    
    With URL:
      python main.py
      > Enter target: https://www.example.com/path
    
    Demo Mode:
      python main.py
      > Run quick demo? (y/n): y
    """
    print(examples)

def print_troubleshooting_tips():
    """Print troubleshooting tips for common issues"""
    tips = """
    🐛 TROUBLESHOOTING TIPS:
    
    Common Issues:
    1. 'ModuleNotFoundError' 
       → Run: pip install -r requirements.txt
    
    2. DNS resolution fails
       → Check internet connection
       → Try a different target (example.com)
    
    3. Permission errors (Linux/Mac)
       → Run with appropriate privileges
    
    4. Firewall blocking scans
       → Check firewall settings
       → Run in controlled environment
    
    5. WHOIS lookup fails
       → Some domains restrict WHOIS access
       → Try different TLD (.com, .org, .net)
    
    Quick Fixes:
    • Reinstall dependencies: pip install --force-reinstall -r requirements.txt
    • Use virtual environment: python -m venv venv && source venv/bin/activate
    • Test connectivity: ping example.com
    • Verify Python version: python --version (requires 3.8+)
    """
    print(tips)

# Test functions
def test_helpers():
    """Test all helper functions"""
    print("🧪 Testing helper functions...")
    
    # Test domain validation
    assert validate_domain("example.com") == True
    assert validate_domain("invalid") == False
    
    # Test IP validation
    assert validate_ip("192.168.1.1") == True
    assert validate_ip("invalid") == False
    
    # Test URL extraction
    assert extract_domain_from_url("https://www.example.com/path") == "example.com"
    assert extract_domain_from_url("example.com") == "example.com"
    
    # Test input sanitization
    assert sanitize_input("example.com") == "example.com"
    assert sanitize_input("example.com;<script>") == "example.comscript"
    
    print("✅ All helper function tests passed!")

if __name__ == "__main__":
    test_helpers()
    print_banner()
    print_usage_examples()