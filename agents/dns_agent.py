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
                'attack_vectors': [],
                'risk_assessment': {},
                'business_context': {}
            }
        }
        
        try:
            # DNS Record Enumeration
            await self.get_dns_records(domain, results)
            
            # WHOIS Lookup
            await self.get_whois_info(domain, results)
            
            # Enhanced subdomain discovery
            await self.find_subdomains(domain, results)
            
            # Comprehensive AI-Powered Analysis
            await self.perform_ai_analysis(results)
            
        except Exception as e:
            results['dns_agent']['error'] = str(e)
        
        return results
    
    async def get_dns_records(self, domain, results):
        """Retrieve various DNS records"""
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        
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
                'country': w.country,
                'address': w.address,
                'city': w.city,
                'state': w.state,
                'zipcode': w.zipcode
            }
        except Exception as e:
            results['dns_agent']['whois_info'] = f"WHOIS lookup failed: {e}"
    
    async def find_subdomains(self, domain, results):
        """Enhanced subdomain discovery with service detection"""
        # Expanded subdomain list for educational institutions
        common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'test', 'admin', 'api', 'blog', 
            'shop', 'portal', 'learn', 'canvas', 'blackboard', 'moodle', 'lms',
            'library', 'research', 'admissions', 'financialaid', 'registrar',
            'hr', 'payroll', 'its', 'helpdesk', 'support', 'portal', 'my',
            'email', 'webmail', 'owa', 'exchange', 'vpn', 'remote', 'ssh',
            'dev', 'staging', 'test', 'qa', 'backup', 'archive', 'media',
            'cdn', 'assets', 'static', 'uploads', 'files', 'docs', 'wiki'
        ]
        
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
            'business_context': self.analyze_business_context(dns_data),
            'risk_assessment': self.perform_risk_assessment(dns_data),
            'recommendations': self.generate_recommendations(dns_data),
            'correlation_analysis': self.correlate_findings(dns_data)
        }
        
        # Add security insights and attack vectors
        dns_data['security_insights'] = self.generate_security_insights(dns_data)
        dns_data['attack_vectors'] = self.identify_attack_vectors(dns_data)
        dns_data['risk_assessment'] = analysis['risk_assessment']
        dns_data['business_context'] = analysis['business_context']
        
        dns_data['ai_analysis'] = analysis
    
    def analyze_domain_characteristics(self, dns_data):
        """AI analysis of domain characteristics with detailed explanations"""
        characteristics = []
        whois_info = dns_data.get('whois_info', {})
        creation_date = whois_info.get('creation_date', '')
        
        # Domain Age Analysis
        if creation_date:
            if '1995' in creation_date:
                characteristics.append({
                    'icon': '🏛️',
                    'finding': 'Established Educational Institution',
                    'explanation': f'Domain registered in 1995 - 29+ years of operation indicates a well-established university with significant digital infrastructure and historical data.',
                    'implication': 'High-value target with extensive digital footprint and potential legacy systems.'
                })
            elif '200' in creation_date:
                characteristics.append({
                    'icon': '💼',
                    'finding': 'Mature Organization',
                    'explanation': 'Domain registered in 2000s - substantial operational history with evolving technology stack.',
                    'implication': 'May have both modern and legacy systems coexisting.'
                })
        
        # Organization Type Analysis
        domain = dns_data.get('target_domain', '').lower()
        if domain.endswith('.edu'):
            characteristics.append({
                'icon': '🎓',
                'finding': 'Educational Institution Confirmed',
                'explanation': '.edu TLD confirms this is an accredited US educational institution with specific security and compliance requirements.',
                'implication': 'Subject to FERPA regulations and educational cybersecurity frameworks.'
            })
        
        return characteristics
    
    def analyze_security_posture(self, dns_data):
        """Comprehensive security posture analysis with explanations"""
        security_notes = []
        dns_records = dns_data.get('dns_records', {})
        
        # Email Security Analysis
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
                if 'spf' in record_lower and 'v=spf1' in record_lower:
                    security_features['spf'] = True
                    security_notes.append({
                        'icon': '🔒',
                        'finding': 'SPF Record Configured',
                        'explanation': 'Sender Policy Framework (SPF) prevents email spoofing by specifying authorized mail servers.',
                        'implication': 'Basic email security implemented, but SPF alone is not sufficient for comprehensive protection.'
                    })
                if 'dmarc' in record_lower:
                    security_features['dmarc'] = True
                if 'dkim' in record_lower:
                    security_features['dkim'] = True
            
            if not security_features['dmarc']:
                security_notes.append({
                    'icon': '⚠️',
                    'finding': 'DMARC Not Implemented',
                    'explanation': 'DMARC (Domain-based Message Authentication) is missing, which allows potential email spoofing and phishing attacks.',
                    'implication': 'High risk of email-based attacks; DMARC implementation recommended.'
                })
        
        # Email Infrastructure Analysis
        mx_records = dns_records.get('MX', [])
        if mx_records and isinstance(mx_records, list):
            for mx in mx_records:
                if 'pphosted.com' in mx.lower():
                    security_notes.append({
                        'icon': '🛡️',
                        'finding': 'Enterprise Email Security (Proofpoint)',
                        'explanation': 'Using Proofpoint hosted email protection - enterprise-grade security with advanced threat protection.',
                        'implication': 'Sophisticated email security in place, but configuration review is still recommended.'
                    })
                    break
        
        return security_notes
    
    def analyze_infrastructure(self, dns_data):
        """Detailed infrastructure analysis with explanations"""
        infrastructure = []
        dns_records = dns_data.get('dns_records', {})
        
        # DNS Infrastructure Analysis
        ns_records = dns_records.get('NS', [])
        if ns_records:
            if len(ns_records) >= 3:
                infrastructure.append({
                    'icon': '🌐',
                    'finding': 'Robust DNS Infrastructure',
                    'explanation': f'Multiple name servers ({len(ns_records)}) provide redundancy and reliability for DNS resolution.',
                    'implication': 'Resilient against DNS outages, but each server represents a potential attack surface.'
                })
        
        # IPv6 Analysis
        aaaa_records = dns_records.get('AAAA', [])
        if aaaa_records and isinstance(aaaa_records, list) and not "Not found" in str(aaaa_records):
            infrastructure.append({
                'icon': '🔗',
                'finding': 'Dual-Stack IPv4/IPv6 Support',
                'explanation': 'Modern infrastructure supporting both IPv4 and IPv6 protocols.',
                'implication': 'Broader attack surface including IPv6-specific vulnerabilities.'
            })
        else:
            infrastructure.append({
                'icon': '🏚️',
                'finding': 'Legacy IPv4-Only Infrastructure',
                'explanation': 'No IPv6 support detected, indicating potential legacy infrastructure.',
                'implication': 'Limited to IPv4 attack vectors, but may indicate outdated systems.'
            })
        
        # Subdomain Infrastructure
        subdomains = dns_data.get('subdomains', [])
        if subdomains:
            infrastructure.append({
                'icon': '🏗️',
                'finding': f'Distributed Infrastructure ({len(subdomains)} subdomains)',
                'explanation': f'Multiple subdomains indicate segmented services and distributed architecture.',
                'implication': 'Larger attack surface requiring comprehensive subdomain testing.'
            })
        
        return infrastructure
    
    def analyze_attack_surface(self, dns_data):
        """Detailed attack surface analysis"""
        attack_surface = []
        dns_records = dns_data.get('dns_records', {})
        subdomains = dns_data.get('subdomains', [])
        
        # Email Attack Surface
        mx_records = dns_records.get('MX', [])
        if mx_records:
            attack_surface.append({
                'icon': '📧',
                'finding': 'Email Infrastructure Exposure',
                'explanation': 'MX records reveal email server infrastructure that can be targeted for phishing, spoofing, or direct attacks.',
                'implication': 'Email servers are prime targets for credential harvesting and business email compromise.'
            })
        
        # Web Infrastructure Analysis
        if any('www' in sub for sub in subdomains):
            attack_surface.append({
                'icon': '🌐',
                'finding': 'Public Web Presence',
                'explanation': 'www subdomain indicates public-facing web services accessible to attackers.',
                'implication': 'Web applications are common entry points for attacks like SQL injection, XSS, and CSRF.'
            })
        
        # Service-Specific Analysis
        service_mapping = {
            'mail': {'icon': '📨', 'service': 'Email Services', 'risks': ['Credential theft', 'Phishing attacks']},
            'api': {'icon': '⚙️', 'service': 'API Endpoints', 'risks': ['API abuse', 'Data exposure']},
            'vpn': {'icon': '🔐', 'service': 'Remote Access', 'risks': ['Credential stuffing', 'VPN vulnerabilities']},
            'admin': {'icon': '👨‍💼', 'service': 'Administrative Interfaces', 'risks': ['Privilege escalation', 'Backdoor access']}
        }
        
        for subdomain in subdomains:
            for service_key, service_info in service_mapping.items():
                if service_key in subdomain:
                    attack_surface.append({
                        'icon': service_info['icon'],
                        'finding': f'{service_info["service"]} Detected',
                        'explanation': f'Subdomain "{subdomain}" indicates {service_info["service"].lower()} with specific security requirements.',
                        'implication': f'Potential risks: {", ".join(service_info["risks"])}'
                    })
        
        return attack_surface
    
    def analyze_business_context(self, dns_data):
        """Analyze business and organizational context"""
        context = []
        domain = dns_data.get('target_domain', '')
        
        # Educational Institution Context
        if domain.endswith('.edu'):
            context.append({
                'icon': '🎓',
                'aspect': 'Institution Type',
                'details': 'Higher Education University',
                'implications': [
                    'Large user base (students, faculty, staff)',
                    'Diverse technology needs across departments',
                    'Research data and intellectual property concerns',
                    'Regulatory compliance (FERPA, GLBA)'
                ]
            })
        
        # Technology Stack Indicators
        txt_records = dns_data.get('dns_records', {}).get('TXT', [])
        tech_indicators = {
            'google-site-verification': 'Google Workspace/Cloud Services',
            'adobe-idp-site-verification': 'Adobe Creative Cloud/Experience Cloud',
            'knowbe4-site-verification': 'Security Awareness Training Platform',
            'openai-domain-verification': 'AI/ML Services Integration',
            'docusign': 'Electronic Signature Platform',
            'amazonses': 'Amazon Simple Email Service'
        }
        
        detected_services = []
        for record in txt_records:
            for indicator, service in tech_indicators.items():
                if indicator in record.lower():
                    detected_services.append(service)
        
        if detected_services:
            context.append({
                'icon': '🛠️',
                'aspect': 'Technology Ecosystem',
                'details': 'Integrated Enterprise Services',
                'implications': [
                    f'Third-party services: {", ".join(detected_services)}',
                    'Expanded attack surface through service integrations',
                    'Dependency on external service providers',
                    'Complex identity and access management'
                ]
            })
        
        return context
    
    def perform_risk_assessment(self, dns_data):
        """Comprehensive risk assessment with scoring"""
        risk_score = 0
        risk_factors = []
        mitigation = []
        
        # Email Security Risks
        txt_records = dns_data.get('dns_records', {}).get('TXT', [])
        has_spf = any('v=spf1' in str(record).lower() for record in txt_records)
        has_dmarc = any('dmarc' in str(record).lower() for record in txt_records)
        
        if not has_dmarc:
            risk_score += 25
            risk_factors.append({
                'risk': 'Email Spoofing Vulnerability',
                'severity': 'High',
                'description': 'Missing DMARC allows attackers to spoof emails from your domain',
                'impact': 'Phishing attacks, reputation damage, financial fraud'
            })
            mitigation.append('Implement DMARC policy with monitoring')
        
        # Infrastructure Risks
        subdomains = dns_data.get('subdomains', [])
        if len(subdomains) > 10:
            risk_score += 15
            risk_factors.append({
                'risk': 'Large Attack Surface',
                'severity': 'Medium',
                'description': 'Multiple subdomains increase potential entry points',
                'impact': 'More targets for attackers, increased maintenance complexity'
            })
            mitigation.append('Regular subdomain inventory and security assessment')
        
        # Service Exposure Risks
        mx_records = dns_data.get('dns_records', {}).get('MX', [])
        if mx_records:
            risk_score += 10
            risk_factors.append({
                'risk': 'Email Service Exposure',
                'severity': 'Medium',
                'description': 'Publicly exposed email infrastructure',
                'impact': 'Target for email-based attacks and service disruption'
            })
            mitigation.append('Email security monitoring and access controls')
        
        # Risk Level Determination
        if risk_score >= 30:
            risk_level = 'High'
        elif risk_score >= 15:
            risk_level = 'Medium'
        else:
            risk_level = 'Low'
        
        return {
            'overall_score': risk_score,
            'risk_level': risk_level,
            'factors': risk_factors,
            'mitigation_recommendations': mitigation
        }
    
    def correlate_findings(self, dns_data):
        """Correlate multiple findings for intelligent insights"""
        correlations = []
        
        # Email Security Correlation
        txt_records = dns_data.get('dns_records', {}).get('TXT', [])
        mx_records = dns_data.get('dns_records', {}).get('MX', [])
        
        has_enterprise_email = any('pphosted.com' in str(mx).lower() for mx in mx_records) if mx_records else False
        has_basic_spf = any('v=spf1' in str(record).lower() for record in txt_records)
        missing_dmarc = not any('dmarc' in str(record).lower() for record in txt_records)
        
        if has_enterprise_email and missing_dmarc:
            correlations.append({
                'type': 'Security Gap',
                'finding': 'Advanced email protection with basic configuration',
                'explanation': 'Enterprise Proofpoint email security is deployed but missing DMARC policy creates a significant security gap.',
                'recommendation': 'Complete email security stack by implementing DMARC alongside existing enterprise protection.'
            })
        
        # Technology Stack Correlation
        detected_services = []
        for record in txt_records:
            if 'google-site-verification' in record.lower():
                detected_services.append('Google Workspace')
            if 'adobe-idp-site-verification' in record.lower():
                detected_services.append('Adobe Cloud')
            if 'knowbe4-site-verification' in record.lower():
                detected_services.append('Security Training')
        
        if len(detected_services) >= 3:
            correlations.append({
                'type': 'Technology Ecosystem',
                'finding': 'Comprehensive enterprise service integration',
                'explanation': f'Multiple enterprise services detected: {", ".join(detected_services)} indicating mature digital transformation.',
                'recommendation': 'Implement centralized identity management and monitor for service-specific vulnerabilities.'
            })
        
        return correlations
    
    def generate_security_insights(self, dns_data):
        """Generate detailed security insights"""
        insights = []
        txt_records = dns_data.get('dns_records', {}).get('TXT', [])
        
        for record in txt_records:
            if 'google-site-verification' in record:
                insights.append({
                    'icon': '🔍',
                    'insight': 'Google Workspace Integration',
                    'details': 'Enterprise productivity and collaboration suite',
                    'security_implication': 'Centralized identity management required, potential for OAuth abuse'
                })
            if 'adobe-idp-site-verification' in record:
                insights.append({
                    'icon': '🎨',
                    'insight': 'Adobe Experience Cloud',
                    'details': 'Digital experience and creative cloud platform',
                    'security_implication': 'Creative asset protection, access control for design resources'
                })
            if 'knowbe4-site-verification' in record:
                insights.append({
                    'icon': '📚',
                    'insight': 'Security Awareness Training',
                    'details': 'KnowBe4 phishing simulation and training platform',
                    'security_implication': 'Indicates proactive security culture, but platform itself needs securing'
                })
            if 'openai-domain-verification' in record:
                insights.append({
                    'icon': '🤖',
                    'insight': 'AI Services Integration',
                    'details': 'OpenAI API or enterprise AI services',
                    'security_implication': 'API key protection, AI model security, data privacy considerations'
                })
        
        return insights
    
    def identify_attack_vectors(self, dns_data):
        """Identify specific attack vectors with explanations"""
        vectors = []
        
        # Email-based Vectors
        vectors.append({
            'category': 'Email Security',
            'vectors': [
                {
                    'vector': 'SPF Record Exploitation',
                    'description': 'Attackers can test SPF record limitations or use allowed third-party services',
                    'techniques': ['SPF record parsing', 'Domain spoofing through allowed senders']
                },
                {
                    'vector': 'Phishing Campaigns',
                    'description': 'Lack of DMARC allows domain spoofing for convincing phishing emails',
                    'techniques': ['CEO fraud', 'Credential harvesting', 'Malware distribution']
                }
            ]
        })
        
        # Infrastructure Vectors
        vectors.append({
            'category': 'DNS & Infrastructure',
            'vectors': [
                {
                    'vector': 'Subdomain Enumeration & Takeover',
                    'description': 'Unused or misconfigured subdomains can be hijacked',
                    'techniques': ['Subdomain brute-forcing', 'CNAME record exploitation']
                },
                {
                    'vector': 'DNS Cache Poisoning',
                    'description': 'Attackers can manipulate DNS resolution to redirect traffic',
                    'techniques': ['DNS spoofing', 'Man-in-the-middle attacks']
                }
            ]
        })
        
        # Service-specific Vectors
        vectors.append({
            'category': 'Third-party Services',
            'vectors': [
                {
                    'vector': 'OAuth & SSO Exploitation',
                    'description': 'Compromised third-party services can provide access to main domain',
                    'techniques': ['OAuth token theft', 'SSO configuration abuse']
                },
                {
                    'vector': 'API Endpoint Discovery',
                    'description': 'Exposed API endpoints through subdomains or service integrations',
                    'techniques': ['API endpoint enumeration', 'Parameter fuzzing']
                }
            ]
        })
        
        return vectors
    
    def generate_recommendations(self, dns_data):
        """Generate prioritized penetration testing recommendations"""
        recommendations = []
        
        # Critical Recommendations
        recommendations.append({
            'priority': 'CRITICAL',
            'recommendation': 'Implement DMARC Email Security',
            'actions': [
                'Deploy DMARC policy starting with monitoring mode (p=none)',
                'Analyze DMARC reports for email traffic patterns',
                'Gradually enforce DMARC policy (p=quarantine -> p=reject)',
                'Monitor for email delivery issues during enforcement'
            ],
            'rationale': 'Missing DMARC exposes the organization to email spoofing and phishing attacks'
        })
        
        # High Priority Recommendations
        recommendations.append({
            'priority': 'HIGH',
            'recommendation': 'Comprehensive Web Application Testing',
            'actions': [
                'Conduct authenticated and unauthenticated web vulnerability scanning',
                'Perform manual testing for business logic flaws',
                'Test for OWASP Top 10 vulnerabilities',
                'Validate input sanitization and output encoding'
            ],
            'rationale': 'Public web services are primary attack vectors for external threats'
        })
        
        # Medium Priority Recommendations
        recommendations.append({
            'priority': 'MEDIUM',
            'recommendation': 'Third-party Service Security Review',
            'actions': [
                'Audit OAuth applications and API integrations',
                'Review service-specific security configurations',
                'Validate access controls for integrated services',
                'Monitor for suspicious activity across platforms'
            ],
            'rationale': 'Multiple third-party services expand the attack surface'
        })
        
        recommendations.append({
            'priority': 'MEDIUM',
            'recommendation': 'Subdomain Security Assessment',
            'actions': [
                'Comprehensive subdomain discovery and enumeration',
                'Test each subdomain for unique vulnerabilities',
                'Check for subdomain takeover opportunities',
                'Validate SSL/TLS configurations across all subdomains'
            ],
            'rationale': 'Distributed infrastructure requires comprehensive security coverage'
        })
        
        return recommendations
    
    def print_ai_analysis_report(self, results):
        """Print a comprehensive AI analysis report"""
        dns_data = results.get('dns_agent', {})
        ai_analysis = dns_data.get('ai_analysis', {})
        
        print("\n" + "="*70)
        print("🤖 COMPREHENSIVE AI ANALYSIS REPORT")
        print("="*70)
        
        # Domain Characteristics
        print("\n📊 DOMAIN CHARACTERISTICS & CONTEXT:")
        print("-" * 50)
        for char in ai_analysis.get('domain_characteristics', []):
            print(f"   {char['icon']} {char['finding']}")
            print(f"      📖 Explanation: {char['explanation']}")
            print(f"      ⚠️  Implication: {char['implication']}")
            print()
        
        # Security Posture
        print("\n🛡️ SECURITY POSTURE ANALYSIS:")
        print("-" * 50)
        for security in ai_analysis.get('security_posture', []):
            print(f"   {security['icon']} {security['finding']}")
            print(f"      📖 Explanation: {security['explanation']}")
            print(f"      ⚠️  Implication: {security['implication']}")
            print()
        
        # Infrastructure Insights
        print("\n🏗️ INFRASTRUCTURE INSIGHTS:")
        print("-" * 50)
        for insight in ai_analysis.get('infrastructure_insights', []):
            print(f"   {insight['icon']} {insight['finding']}")
            print(f"      📖 Explanation: {insight['explanation']}")
            print(f"      ⚠️  Implication: {insight['implication']}")
            print()
        
        # Business Context
        print("\n🏢 BUSINESS & ORGANIZATIONAL CONTEXT:")
        print("-" * 50)
        for context in ai_analysis.get('business_context', []):
            print(f"   {context['icon']} {context['aspect']}: {context['details']}")
            print("      Implications:")
            for implication in context['implications']:
                print(f"        • {implication}")
            print()
        
        # Risk Assessment
        print("\n⚠️  QUANTITATIVE RISK ASSESSMENT:")
        print("-" * 50)
        risk_assessment = ai_analysis.get('risk_assessment', {})
        print(f"   Overall Risk Score: {risk_assessment.get('overall_score', 0)}/100")
        print(f"   Risk Level: {risk_assessment.get('risk_level', 'Unknown')}")
        
        factors = risk_assessment.get('factors', [])
        if factors:
            print("\n   Identified Risk Factors:")
            for factor in factors:
                print(f"     🚨 {factor['risk']} ({factor['severity']})")
                print(f"        Description: {factor['description']}")
                print(f"        Potential Impact: {factor['impact']}")
                print()
        
        # Correlation Analysis
        print("\n🔗 INTELLIGENT CORRELATION ANALYSIS:")
        print("-" * 50)
        correlations = ai_analysis.get('correlation_analysis', [])
        if correlations:
            for correlation in correlations:
                print(f"   {correlation['type']}: {correlation['finding']}")
                print(f"      📖 Explanation: {correlation['explanation']}")
                print(f"      💡 Recommendation: {correlation['recommendation']}")
                print()
        else:
            print("   No significant correlations identified")
        
        # Security Insights
        print("\n🔍 SECURITY INSIGHTS & TECHNOLOGY DETECTION:")
        print("-" * 50)
        insights = dns_data.get('security_insights', [])
        if insights:
            for insight in insights:
                print(f"   {insight['icon']} {insight['insight']}")
                print(f"      Details: {insight['details']}")
                print(f"      Security Implication: {insight['security_implication']}")
                print()
        else:
            print("   No specific security insights detected")
        
        # Attack Vectors
        print("\n⚡ IDENTIFIED ATTACK VECTORS & TECHNIQUES:")
        print("-" * 50)
        vectors = dns_data.get('attack_vectors', [])
        for category in vectors:
            print(f"   📂 {category['category']}:")
            for vector in category['vectors']:
                print(f"     🎯 {vector['vector']}")
                print(f"        Description: {vector['description']}")
                print(f"        Techniques: {', '.join(vector['techniques'])}")
                print()
        
        # Recommendations
        print("\n💡 PRIORITIZED PENETRATION TESTING RECOMMENDATIONS:")
        print("-" * 50)
        recommendations = ai_analysis.get('recommendations', [])
        for rec in recommendations:
            print(f"   {self.get_priority_icon(rec['priority'])} [{rec['priority']}] {rec['recommendation']}")
            print(f"      Rationale: {rec['rationale']}")
            print("      Actions:")
            for action in rec['actions']:
                print(f"        • {action}")
            print()
        
        print("="*70)
    
    def get_priority_icon(self, priority):
        """Get icon for priority level"""
        icons = {
            'CRITICAL': '🚨',
            'HIGH': '🔴', 
            'MEDIUM': '🟡',
            'LOW': '🟢'
        }
        return icons.get(priority, '⚪')

# Example usage and testing
async def test_ai_analysis():
    """Test function to demonstrate enhanced AI analysis"""
    agent = DNSReconAgent()
    test_domain = "example.com"
    
    print("🧪 Testing Enhanced AI Analysis...")
    results = await agent.investigate(test_domain)
    agent.print_ai_analysis_report(results)

if __name__ == "__main__":
    asyncio.run(test_ai_analysis())