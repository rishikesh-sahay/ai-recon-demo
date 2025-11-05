import dns.resolver
import whois
import asyncio
import aiohttp
from urllib.parse import urlparse
import re
from datetime import datetime

class DNSReconAgent:
    def __init__(self):
        self.name = "DNS Reconnaissance Agent"
        self.description = "Performs DNS enumeration and domain information gathering with AI-powered analysis"
    
    async def investigate(self, domain):
        """Perform DNS reconnaissance on target domain"""
        print(f"🔍 DNS Agent investigating: {domain}")
        
        results = {
            'dns_agent': {
                'target_domain': domain,
                'dns_records': {},
                'whois_info': {},
                'subdomains': [],
                'ai_analysis': {},
                'security_insights': [],
                'attack_vectors': []
            }
        }
        
        try:
            # DNS Record Enumeration
            await self.get_dns_records(domain, results)
            
            # WHOIS Lookup
            await self.get_whois_info(domain, results)
            
            # Basic subdomain discovery (simulated for demo)
            await self.find_subdomains(domain, results)
            
            # AI-Powered Analysis
            await self.perform_ai_analysis(results)
            
        except Exception as e:
            results['dns_agent']['error'] = str(e)
        
        return results
    
    async def get_dns_records(self, domain, results):
        """Retrieve various DNS records"""
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                results['dns_agent']['dns_records'][record_type] = [
                    str(rdata) for rdata in answers
                ]
            except Exception as e:
                results['dns_agent']['dns_records'][record_type] = f"Not found: {e}"
    
    async def get_whois_info(self, domain, results):
        """Get WHOIS information"""
        try:
            w = whois.whois(domain)
            # Handle cases where dates might be lists
            creation_date = w.creation_date
            expiration_date = w.expiration_date
            
            if isinstance(creation_date, list):
                creation_date = creation_date[0] if creation_date else None
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0] if expiration_date else None
            
            results['dns_agent']['whois_info'] = {
                'registrar': w.registrar,
                'creation_date': str(creation_date),
                'expiration_date': str(expiration_date),
                'name_servers': w.name_servers,
                'emails': w.emails,
                'org': w.org,
                'country': w.country
            }
        except Exception as e:
            results['dns_agent']['whois_info'] = f"WHOIS lookup failed: {e}"
    
    async def find_subdomains(self, domain, results):
        """Simulate subdomain discovery"""
        # For demo purposes - in real scenario, you'd use wordlists
        common_subdomains = ['www', 'mail', 'ftp', 'localhost', 'test', 'admin', 'api', 'blog', 'shop', 'portal']
        
        discovered = []
        for sub in common_subdomains:
            subdomain = f"{sub}.{domain}"
            try:
                # Try to resolve subdomain
                dns.resolver.resolve(subdomain, 'A')
                discovered.append(subdomain)
            except:
                pass
        
        results['dns_agent']['subdomains'] = discovered
    
    async def perform_ai_analysis(self, results):
        """Perform comprehensive AI-powered analysis"""
        dns_data = results['dns_agent']
        
        analysis = {
            'domain_characteristics': self.analyze_domain_characteristics(dns_data),
            'security_posture': self.analyze_security_posture(dns_data),
            'infrastructure_insights': self.analyze_infrastructure(dns_data),
            'attack_surface': self.analyze_attack_surface(dns_data),
            'recommendations': self.generate_recommendations(dns_data)
        }
        
        # Add security insights and attack vectors
        dns_data['security_insights'] = self.generate_security_insights(dns_data)
        dns_data['attack_vectors'] = self.identify_attack_vectors(dns_data)
        
        dns_data['ai_analysis'] = analysis
    
    def analyze_domain_characteristics(self, dns_data):
        """AI analysis of domain characteristics"""
        characteristics = []
        whois_info = dns_data.get('whois_info', {})
        creation_date = whois_info.get('creation_date', '')
        
        if creation_date and '199' in creation_date:
            characteristics.append("🏛️  Established organization (domain registered in 1990s)")
        elif creation_date and '200' in creation_date:
            characteristics.append("💼 Medium-aged organization")
        elif creation_date and '202' in creation_date:
            characteristics.append("🚀 Recently established organization")
        
        # Analyze organization type
        org = whois_info.get('org', '').lower() if whois_info.get('org') else ''
        if any(edu in org for edu in ['university', 'college', 'edu']):
            characteristics.append("🎓 Educational institution identified")
        elif any(gov in org for gov in ['government', 'gov']):
            characteristics.append("🏛️  Government organization identified")
        elif any(corp in org for corp in ['corp', 'inc', 'ltd']):
            characteristics.append("💼 Corporate organization identified")
        
        return characteristics
    
    def analyze_security_posture(self, dns_data):
        """AI analysis of security posture from DNS records"""
        security_notes = []
        dns_records = dns_data.get('dns_records', {})
        
        # Analyze TXT records for security configurations
        txt_records = dns_records.get('TXT', [])
        if isinstance(txt_records, list):
            security_features = {
                'spf': False,
                'dmarc': False,
                'dkim': False,
                'https': False
            }
            
            for record in txt_records:
                record_lower = record.lower()
                if 'spf' in record_lower:
                    security_features['spf'] = True
                if 'dmarc' in record_lower:
                    security_features['dmarc'] = True
                if 'dkim' in record_lower:
                    security_features['dkim'] = True
                if 'https' in record_lower or 'http' in record_lower:
                    security_features['https'] = True
            
            if security_features['spf']:
                security_notes.append("🔒 SPF configured - email spoofing protection")
            else:
                security_notes.append("⚠️  SPF not found - email spoofing risk")
                
            if security_features['dmarc']:
                security_notes.append("🔒 DMARC configured - advanced email security")
            else:
                security_notes.append("⚠️  DMARC not found - consider implementing")
        
        # Analyze MX records for email security
        mx_records = dns_records.get('MX', [])
        if mx_records and isinstance(mx_records, list):
            enterprise_providers = ['proofpoint', 'mimecast', 'barracuda', 'office365', 'google']
            for mx in mx_records:
                if any(provider in mx.lower() for provider in enterprise_providers):
                    security_notes.append("📧 Enterprise email security provider detected")
                    break
        
        return security_notes
    
    def analyze_infrastructure(self, dns_data):
        """AI analysis of infrastructure setup"""
        infrastructure = []
        dns_records = dns_data.get('dns_records', {})
        
        # Analyze name servers
        ns_records = dns_records.get('NS', [])
        if ns_records:
            if len(ns_records) >= 3:
                infrastructure.append("🌐 Robust DNS infrastructure (multiple name servers)")
            else:
                infrastructure.append("🌐 Basic DNS infrastructure")
        
        # Analyze IPv6 support
        aaaa_records = dns_records.get('AAAA', [])
        if aaaa_records and isinstance(aaaa_records, list) and not "Not found" in str(aaaa_records):
            infrastructure.append("🔗 IPv6 enabled - modern infrastructure")
        else:
            infrastructure.append("🔗 IPv6 not detected - legacy infrastructure")
        
        # Analyze subdomains
        subdomains = dns_data.get('subdomains', [])
        if len(subdomains) > 5:
            infrastructure.append("🏗️  Complex infrastructure (multiple subdomains)")
        elif len(subdomains) > 2:
            infrastructure.append("🏗️  Moderate infrastructure")
        else:
            infrastructure.append("🏗️  Simple infrastructure")
        
        return infrastructure
    
    def analyze_attack_surface(self, dns_data):
        """AI analysis of potential attack surface"""
        attack_surface = []
        dns_records = dns_data.get('dns_records', {})
        subdomains = dns_data.get('subdomains', [])
        
        # Email attack surface
        mx_records = dns_records.get('MX', [])
        if mx_records and isinstance(mx_records, list):
            attack_surface.append("📧 Email servers present - phishing/social engineering vector")
        
        # Subdomain attack surface
        if subdomains:
            sensitive_subdomains = ['admin', 'api', 'portal', 'secure', 'vpn']
            found_sensitive = [sub for sub in subdomains if any(s in sub for s in sensitive_subdomains)]
            if found_sensitive:
                attack_surface.append(f"🎯 Sensitive subdomains found: {', '.join(found_sensitive)}")
        
        # Service discovery through common subdomains
        service_mapping = {
            'mail': 'Email services',
            'ftp': 'File transfer',
            'api': 'Application programming interface',
            'blog': 'Content management',
            'shop': 'E-commerce'
        }
        
        for subdomain in subdomains:
            for service_key, service_name in service_mapping.items():
                if service_key in subdomain:
                    attack_surface.append(f"🛠️  {service_name} detected via {subdomain}")
        
        return attack_surface
    
    def generate_recommendations(self, dns_data):
        """AI-generated recommendations for penetration testing"""
        recommendations = []
        dns_records = dns_data.get('dns_records', {})
        
        # Web application testing
        if any(port in str(dns_data) for port in ['80', '443']):
            recommendations.append("🎯 **Priority**: Conduct web application security testing")
            recommendations.append("🔍 Perform directory brute-forcing on web servers")
            recommendations.append("🌐 Check for common web vulnerabilities (XSS, SQLi, CSRF)")
        
        # Email security testing
        mx_records = dns_records.get('MX', [])
        if mx_records:
            recommendations.append("📧 **Priority**: Email security assessment")
            recommendations.append("🛡️  Test for open relays on SMTP servers")
            recommendations.append("📨 Conduct phishing simulation exercises")
        
        # Infrastructure testing
        if len(dns_data.get('subdomains', [])) > 3:
            recommendations.append("🏗️  **Priority**: Subdomain enumeration and testing")
            recommendations.append("🔎 Perform comprehensive subdomain discovery")
            recommendations.append("🎯 Test each subdomain for unique vulnerabilities")
        
        # DNS-specific tests
        recommendations.append("🔐 **Standard**: DNS security checks")
        recommendations.append("📊 Check for DNS zone transfer vulnerabilities")
        recommendations.append("🛡️  Verify DNSSEC implementation (if applicable)")
        
        return recommendations
    
    def generate_security_insights(self, dns_data):
        """Generate security-focused insights"""
        insights = []
        dns_records = dns_data.get('dns_records', {})
        
        # TXT record analysis
        txt_records = dns_records.get('TXT', [])
        if isinstance(txt_records, list):
            for record in txt_records:
                if 'google-site-verification' in record:
                    insights.append("🔍 Google services integration detected")
                if 'adobe-idp-site-verification' in record:
                    insights.append("🎨 Adobe services integration detected")
                if 'openai-domain-verification' in record:
                    insights.append("🤖 OpenAI services integration detected")
                if 'knowbe4-site-verification' in record:
                    insights.append("📚 KnowBe4 security awareness platform detected")
        
        # MX record analysis
        mx_records = dns_records.get('MX', [])
        if mx_records:
            if any('pphosted.com' in mx for mx in mx_records):
                insights.append("📧 Proofpoint enterprise email protection detected")
        
        return insights
    
    def identify_attack_vectors(self, dns_data):
        """Identify specific attack vectors"""
        vectors = []
        dns_records = dns_data.get('dns_records', {})
        subdomains = dns_data.get('subdomains', [])
        
        # Web-based vectors
        if any(port in str(dns_data) for port in ['80', '443']):
            vectors.append("🌐 **Web Application Attacks**: SQL injection, XSS, CSRF")
            vectors.append("🔐 **Authentication Attacks**: Brute force, credential stuffing")
        
        # Email-based vectors
        if dns_records.get('MX'):
            vectors.append("📧 **Email Attacks**: Phishing, business email compromise")
            vectors.append("🛡️  **Email Security**: SPF/DKIM/DMARC bypass attempts")
        
        # Infrastructure vectors
        if subdomains:
            vectors.append("🏗️  **Subdomain Takeover**: Check for orphaned subdomains")
            vectors.append("🔍 **Information Disclosure**: Subdomain enumeration")
        
        # DNS-specific vectors
        vectors.append("🎯 **DNS Attacks**: Zone transfer, cache poisoning, DDoS")
        
        return vectors

    def print_ai_analysis_report(self, results):
        """Print a formatted AI analysis report"""
        dns_data = results.get('dns_agent', {})
        ai_analysis = dns_data.get('ai_analysis', {})
        
        print("\n" + "="*60)
        print("🤖 AI ANALYSIS REPORT")
        print("="*60)
        
        # Domain Characteristics
        print("\n📊 DOMAIN CHARACTERISTICS:")
        for char in ai_analysis.get('domain_characteristics', []):
            print(f"   • {char}")
        
        # Security Posture
        print("\n🛡️ SECURITY POSTURE:")
        for security in ai_analysis.get('security_posture', []):
            print(f"   • {security}")
        
        # Infrastructure Insights
        print("\n🏗️ INFRASTRUCTURE INSIGHTS:")
        for insight in ai_analysis.get('infrastructure_insights', []):
            print(f"   • {insight}")
        
        # Attack Surface
        print("\n🎯 ATTACK SURFACE ANALYSIS:")
        for surface in ai_analysis.get('attack_surface', []):
            print(f"   • {surface}")
        
        # Security Insights
        print("\n🔍 SECURITY INSIGHTS:")
        insights = dns_data.get('security_insights', [])
        if insights:
            for insight in insights:
                print(f"   • {insight}")
        else:
            print("   • No specific security insights detected")
        
        # Attack Vectors
        print("\n⚡ IDENTIFIED ATTACK VECTORS:")
        vectors = dns_data.get('attack_vectors', [])
        for vector in vectors:
            print(f"   • {vector}")
        
        # Recommendations
        print("\n💡 PENETRATION TESTING RECOMMENDATIONS:")
        for i, recommendation in enumerate(ai_analysis.get('recommendations', []), 1):
            print(f"   {i}. {recommendation}")
        
        print("="*60)

# Example usage and testing
async def test_ai_analysis():
    """Test function to demonstrate AI analysis"""
    agent = DNSReconAgent()
    test_domain = "example.com"
    
    print("🧪 Testing AI Analysis...")
    results = await agent.investigate(test_domain)
    agent.print_ai_analysis_report(results)

if __name__ == "__main__":
    asyncio.run(test_ai_analysis())