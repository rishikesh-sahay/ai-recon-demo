import asyncio
import json
import time
from agents.dns_agent import DNSReconAgent
from agents.port_agent import PortScanAgent
from utils.helpers import validate_domain, validate_ip, extract_domain_from_url, print_banner

class ReconnaissanceMaster:
    def __init__(self):
        self.agents = {
            'dns': DNSReconAgent(),
            'port': PortScanAgent()
        }
        self.results = {}
    
    async def orchestrate_recon(self, target):
        """Orchestrate multiple reconnaissance agents"""
        print(f"🤖 Starting AI-powered reconnaissance on: {target}")
        print("=" * 60)
        
        # Clean and validate target input
        clean_target = extract_domain_from_url(target)
        print(f"🎯 Cleaned target: {clean_target}")
        
        tasks = []
        
        # Validate target and create tasks
        if validate_domain(clean_target):
            print("🔍 Activating DNS Reconnaissance Agent...")
            tasks.append(self.agents['dns'].investigate(clean_target))
        
        if validate_ip(clean_target) or validate_domain(clean_target):
            print("🔍 Activating Port Scanning Agent...")
            # For demo, we'll use a limited port range
            tasks.append(self.agents['port'].investigate(clean_target, ports=[80, 443, 22, 21, 25, 53, 8080, 8443]))
        
        if not tasks:
            print("❌ Invalid target. Please provide a valid domain or IP address.")
            return {}
        
        # Execute all agents concurrently
        print("\n🚀 Executing AI agents concurrently...")
        print("⏳ Agents are analyzing the target...")
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Compile results
        for result in results:
            if not isinstance(result, Exception):
                self.results.update(result)
        
        return self.results
    
    def generate_report(self):
        """Generate a comprehensive reconnaissance report"""
        print("\n" + "=" * 60)
        print("📊 RECONNAISSANCE REPORT")
        print("=" * 60)
        
        for agent_type, findings in self.results.items():
            print(f"\n🔍 {agent_type.upper()} FINDINGS:")
            print("-" * 40)
            
            if isinstance(findings, dict):
                for key, value in findings.items():
                    if key in ['ai_analysis', 'security_insights', 'attack_vectors']:
                        continue  # Skip these for now, handled separately
                    
                    if isinstance(value, list):
                        print(f"  {key.replace('_', ' ').title()}:")
                        for item in value:
                            if isinstance(item, dict):
                                for k, v in item.items():
                                    print(f"    - {k}: {v}")
                            else:
                                print(f"    - {item}")
                    elif isinstance(value, dict):
                        print(f"  {key.replace('_', ' ').title()}:")
                        for k, v in value.items():
                            if isinstance(v, list):
                                print(f"    {k}:")
                                for item in v:
                                    print(f"      - {item}")
                            else:
                                print(f"    {k}: {v}")
                    else:
                        print(f"  {key.replace('_', ' ').title()}: {value}")
            else:
                print(f"  {findings}")
    
    def generate_ai_analysis_report(self):
        """Generate the AI-powered analysis report"""
        if 'dns_agent' in self.results:
            print("\n" + "=" * 60)
            print("🤖 AI-POWERED ANALYSIS & RECOMMENDATIONS")
            print("=" * 60)
            
            dns_agent = self.agents['dns']
            dns_agent.print_ai_analysis_report(self.results)
    
    def generate_executive_summary(self):
        """Generate an executive summary for quick insights"""
        print("\n" + "=" * 60)
        print("📈 EXECUTIVE SUMMARY")
        print("=" * 60)
        
        # DNS Summary
        if 'dns_agent' in self.results:
            dns_data = self.results['dns_agent']
            print("\n🌐 DOMAIN OVERVIEW:")
            print(f"  • Target: {dns_data.get('target_domain', 'N/A')}")
            
            # Domain age
            whois_info = dns_data.get('whois_info', {})
            creation_date = whois_info.get('creation_date', '')
            if creation_date and '199' in creation_date:
                print("  • Age: Established (1990s)")
            elif creation_date and '200' in creation_date:
                print("  • Age: Mature (2000s)")
            elif creation_date and '202' in creation_date:
                print("  • Age: Recent")
            
            # Subdomains
            subdomains = dns_data.get('subdomains', [])
            print(f"  • Subdomains Found: {len(subdomains)}")
            
            # Security features
            txt_records = dns_data.get('dns_records', {}).get('TXT', [])
            security_features = []
            if any('spf' in str(record).lower() for record in txt_records):
                security_features.append("SPF")
            if any('dmarc' in str(record).lower() for record in txt_records):
                security_features.append("DMARC")
            
            if security_features:
                print(f"  • Security Features: {', '.join(security_features)}")
        
        # Port Scan Summary
        if 'port_agent' in self.results:
            port_data = self.results['port_agent']
            open_ports = port_data.get('open_ports', [])
            print(f"\n🔓 OPEN PORTS: {len(open_ports)}")
            for port_info in open_ports:
                print(f"  • Port {port_info['port']} ({port_info['service']})")
        
        # Quick Risk Assessment
        print(f"\n⚠️  INITIAL RISK ASSESSMENT:")
        risk_factors = []
        
        if 'port_agent' in self.results:
            open_ports = self.results['port_agent'].get('open_ports', [])
            web_ports = [80, 443, 8080, 8443]
            if any(port_info['port'] in web_ports for port_info in open_ports):
                risk_factors.append("Web services exposed")
            
            if any(port_info['port'] in [21, 22, 23] for port_info in open_ports):
                risk_factors.append("Remote access services")
        
        if 'dns_agent' in self.results:
            dns_data = self.results['dns_agent']
            subdomains = dns_data.get('subdomains', [])
            if len(subdomains) > 5:
                risk_factors.append("Large attack surface (multiple subdomains)")
            
            mx_records = dns_data.get('dns_records', {}).get('MX', [])
            if mx_records:
                risk_factors.append("Email infrastructure present")
        
        if risk_factors:
            for factor in risk_factors:
                print(f"  • {factor}")
        else:
            print("  • Minimal exposed services detected")
        
        print(f"\n🎯 RECOMMENDED FOCUS AREAS:")
        if any(port_info['port'] in [80, 443] for port_info in open_ports):
            print("  • Web application security testing")
        if any('admin' in sub for sub in subdomains):
            print("  • Administrative interface testing")
        if mx_records:
            print("  • Email security assessment")

async def main():
    # Print banner
    print_banner()
    
    # Initialize the reconnaissance master
    recon_master = ReconnaissanceMaster()
    
    # Get target from user
    print("\n🎯 TARGET SELECTION")
    print("-" * 30)
    print("Examples: example.com, google.com, 127.0.0.1")
    print("You can also use URLs: https://example.com")
    target = input("\nEnter target domain or IP: ").strip()
    
    if not target:
        target = "example.com"  # Default for demo
        print(f"Using default target: {target}")
    
    try:
        start_time = time.time()
        
        # Execute reconnaissance
        results = await recon_master.orchestrate_recon(target)
        
        if not results:
            print("❌ No reconnaissance data collected. Exiting.")
            return
        
        # Generate reports
        recon_master.generate_executive_summary()
        recon_master.generate_report()
        recon_master.generate_ai_analysis_report()
        
        # Save results to file
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        filename = f'recon_results_{timestamp}.json'
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        end_time = time.time()
        duration = end_time - start_time
        
        print(f"\n" + "=" * 60)
        print("📦 SESSION SUMMARY")
        print("=" * 60)
        print(f"✅ Reconnaissance completed in {duration:.2f} seconds")
        print(f"💾 Results saved to: {filename}")
        print(f"🎯 Target analyzed: {target}")
        print(f"🤖 Agents executed: {len(recon_master.agents)}")
        print("=" * 60)
        
        # Show quick tips
        print("\n💡 QUICK NEXT STEPS:")
        print("  • Review AI analysis for testing priorities")
        print("  • Check open ports for service enumeration")
        print("  • Validate subdomains for additional targets")
        print("  • Use findings to plan penetration testing approach")
        
    except KeyboardInterrupt:
        print(f"\n❌ Reconnaissance interrupted by user.")
    except Exception as e:
        print(f"\n❌ Error during reconnaissance: {e}")
        print("💡 Troubleshooting tips:")
        print("  • Check internet connection")
        print("  • Verify target format (use domain.com or IP)")
        print("  • Ensure all dependencies are installed")
        print("  • Try a different target like 'example.com'")

def quick_demo():
    """Run a quick demo with example.com"""
    print("🚀 Running quick demo with example.com...")
    print("This demonstrates the AI reconnaissance capabilities.")
    
    async def demo():
        recon_master = ReconnaissanceMaster()
        results = await recon_master.orchestrate_recon("example.com")
        recon_master.generate_executive_summary()
        recon_master.generate_ai_analysis_report()
    
    asyncio.run(demo())

if __name__ == "__main__":
    # Check if user wants quick demo
    response = input("Run quick demo? (y/n): ").strip().lower()
    if response in ['y', 'yes', 'demo']:
        quick_demo()
    else:
        asyncio.run(main())