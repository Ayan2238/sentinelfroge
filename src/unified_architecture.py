from core.reconnaissance import ReconMaster
from core.vulnerability import VulnPredictor
from core.exploit import ExploitEngine
from core.post_exploit import LateralMovementSimulator
from utils.report_generator import generate_report

class SentinelForge:
    def __init__(self):
        # Initialize all modules
        self.recon = ReconMaster()
        self.vuln_scanner = VulnPredictor()
        self.exploit_engine = ExploitEngine()
        self.post_exploit = LateralMovementSimulator()
    
    def run_full_scan(self, target):
        """Orchestrate the entire pentesting workflow"""
        print(f"[*] Starting full scan for: {target}")
        
        # Step 1: Reconnaissance
        print("[+] Running reconnaissance...")
        attack_surface = self.recon.map_attack_surface(target)
        
        # Step 2: Vulnerability Scanning
        print("[+] Scanning for vulnerabilities...")
        vulnerabilities = self.vuln_scanner.detect_zero_day(attack_surface)
        
        # Step 3: Exploit Testing
        print("[+] Testing exploits...")
        exploits = self.exploit_engine.generate_exploit(vulnerabilities)
        
        # Step 4: Post-Exploitation Analysis
        print("[+] Simulating post-exploitation...")
        attack_paths = self.post_exploit.simulate_attack_paths(target)
        data_leaks = self.post_exploit.detect_data_leaks(attack_surface)
        
        # Step 5: Generate Report
        print("[+] Generating report...")
        report_data = {
            "target": target,
            "attack_surface": attack_surface,
            "vulnerabilities": vulnerabilities,
            "exploits": exploits,
            "attack_paths": attack_paths,
            "data_leaks": data_leaks
        }
        generate_report(report_data)
        
        print("[+] Scan complete! Report saved to report.html")

# Example usage
if __name__ == "__main__":
    scanner = SentinelForge()
    scanner.run_full_scan("example.com")