import os
import shodan
from pywayback import WaybackMachine
from neo4j import GraphDatabase
import subprocess

class ReconMaster:
    def __init__(self):
        # Initialize Neo4j driver for attack surface visualization
        neo4j_uri = os.getenv("SF_NEO4J_URI", "bolt://localhost:7687")
        neo4j_user = os.getenv("SF_NEO4J_USER", "neo4j")
        neo4j_password = os.getenv("SF_NEO4J_PASSWORD")
        if not neo4j_password:
            raise RuntimeError("SF_NEO4J_PASSWORD must be set before using Neo4j integration")

        self.neo4j_driver = GraphDatabase.driver(
            neo4j_uri,
            auth=(neo4j_user, neo4j_password)
        )
        
        # Initialize Shodan API
        shodan_api_key = os.getenv("SF_SHODAN_API_KEY")
        if not shodan_api_key:
            raise RuntimeError("SF_SHODAN_API_KEY must be set before using Shodan integration")
        self.shodan_api = shodan.Shodan(shodan_api_key)
    
    def map_attack_surface(self, domain):
        """Generate interactive attack graph for the target domain"""
        print(f"[*] Mapping attack surface for: {domain}")
        
        # Step 1: Get Wayback Machine archives
        print("[+] Fetching Wayback Machine archives...")
        wayback = WaybackMachine()
        archived_urls = wayback.search(f"{domain}/*")
        
        # Step 2: Discover services with Shodan
        print("[+] Querying Shodan for host information...")
        try:
            services = self.shodan_api.search(f"hostname:{domain}")
        except shodan.APIError as e:
            print(f"[-] Shodan error: {e}")
            services = []
        
        # Step 3: Build Neo4j graph
        print("[+] Building attack surface graph...")
        with self.neo4j_driver.session() as session:
            session.write_transaction(self._create_subdomain_nodes, domain)
            session.write_transaction(self._link_services, services)
        
        print("[+] Attack surface mapping complete!")

    def _create_subdomain_nodes(self, tx, domain):
        """Create subdomain nodes in Neo4j"""
        # Use Sublist3r for subdomain enumeration
        print("[+] Enumerating subdomains...")
        subdomains = subprocess.check_output(
            ["sublist3r", "-d", domain, "-o", "-"],
            text=True,
        ).splitlines()
        
        for sd in subdomains:
            tx.run("CREATE (s:Subdomain {name: $name})", name=sd)

    def _link_services(self, tx, services):
        """Link discovered services to subdomains"""
        print("[+] Linking services to subdomains...")
        for service in services:
            tx.run(
                "MATCH (s:Subdomain {name: $subdomain}) "
                "CREATE (s)-[:HOSTS]->(svc:Service {port: $port, product: $product})",
                subdomain=service["hostnames"][0],
                port=service["port"],
                product=service["product"]
            )

# Example usage
if __name__ == "__main__":
    recon = ReconMaster()
    recon.map_attack_surface("example.com")
