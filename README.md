# SentinelForge
AI-Powered Web Security Scanner & Penetration Testing Framework

SentinelForge is an advanced AI-driven security scanner designed to automate reconnaissance, vulnerability detection, and exploitation for web applications. It combines machine learning, OSINT automation, and deep security analysis to help ethical hackers and penetration testers efficiently identify security risks.
�Why SentinelForge?
 Automated Vulnerability Scanning Detects XSS, SQL Injection, API security flaws, and cloud misconfigurations.
 AI-Enhanced Detectio Uses machine learning to reduce false positives and prioritize critical threats.
 Subdomain & OSINT Recon Automates data gathering from Wayback Machine, certificate logs, and GitHub leaks.
 Cloud & API Security Testing Finds exposed AWS S3 buckets, API endpoints, and authentication flaws.
 Attack Surface Mapping Uses Neo4j to visualize relationships between assets and vulnerabilities.
 Automated Reports Generates detailed, structured HTML reports with recommended fixes.
 Seamless Integration Works with Shodan, WHOIS, AWS, and other security APIs for real-time intelligence.
�Features & Modules
Reconnaissance Suite

    Subdomain Discovery
  Finds hidden subdomains via certificate logs, DNS enumeration, and API integrations.
    Wayback URL Extraction Scrapes historical endpoints from the Wayback Machine for OSINT.
    GitHub & Certificate Analysis  Detects leaked secrets and SSL misconfigurations.

 Vulnerability Scanner

    XSS & SQL Injection Testing Uses smart payloads for automated security testing.
    API Endpoint Detection Identifies exposed API routes and security misconfigurations.
    AWS S3 Bucket Finder Checks for misconfigured cloud storage.

3️⃣ Exploitation Framework

    AI-Generated Payloads – Crafts dynamic attack payloads based on the target’s tech stack.
    Post-Exploitation Analysis – Simulates lateral movement and data exfiltration risks.

4️⃣ Attack Surface Visualization

    Neo4j Integration – Displays asset relationships in an interactive attack graph.

5️⃣ Automated Reporting

    Generates HTML reports with vulnerability findings, impact analysis, and remediation steps.

🚀 Installation & Setup
🔹 Prerequisites

Ensure you have the following installed:

    Python 3.8+
    Pip (Python package manager)
    Google Chrome (for Selenium-based scanning)
    Neo4j (for attack surface mapping)

�� Clone the Repository

git clone https://github.com/YOUR_USERNAME/SentinelForge.git
cd SentinelForge

🔹 Install Dependencies

pip install -r requirements.txt

🔹 Set Up Neo4j (Optional - for Attack Graphs)

    Download and install Neo4j: Neo4j Download
    Start the database:

    neo4j console

    Set authentication credentials in config.py.

⚡ How to Use SentinelForge
🔹 Basic Usage

To scan a target domain:

python sentinelforge.py -d example.com --shodan YOUR_SHODAN_API_KEY

🔹 Scan Results – Check the generated report.html for detailed findings.
🔹 Advanced Usage

    With Neo4j Attack Graph:

python sentinelforge.py -d example.com --shodan YOUR_SHODAN_API_KEY --neo4j-uri bolt://localhost:7687 --neo4j-user neo4j --neo4j-pass YOUR_PASSWORD

Saving Reports to a Custom File:

    python sentinelforge.py -d example.com -o my_custom_report.html

📂 File Structure

📦 SentinelForge  
 ┣ 📂 modules             # All scanning and exploitation modules  
 ┣ 📂 reports             # Stores generated HTML reports  
 ┣ 📂 screenshots         # Stores captured screenshots  
 ┣ 📜 sentinelforge.py    # Main execution file  
 ┣ 📜 config.py           # API keys and configuration settings  
 ┣ 📜 requirements.txt    # Dependencies  
 ┣ 📜 README.md           # This file  

🔑 API Keys & Configuration

To use APIs like Shodan, WHOIS, AWS, and more, add your API keys in config.py:

SHODAN_API_KEY = "your_shodan_api_key"
WHOISXML_API_KEY = "your_whoisxml_api_key"
AWS_ACCESS_KEY = "your_aws_access_key"
AWS_SECRET_KEY = "your_aws_secret_key"

📊 Sample Report Output

Once a scan completes, you’ll get a detailed report like this:
📜 report.html
✔ Subdomain Findings
✔ API Endpoints Discovered
✔ Vulnerabilities (XSS, SQLi, etc.)
✔ Recommendations & Fixes
🤝 Contributing

💡 Want to improve SentinelForge? Fork the repo and submit a PR!
🔹 Steps to Contribute:

    Fork the repo
    Create a new branch:

git checkout -b new-feature

Make your changes & commit:

git commit -m "Added a new feature"

Push and open a pull request:

    git push origin new-feature

📜 Legal Disclaimer

🚨 For ethical use only! This tool is intended for security research and authorized penetration testing. Do NOT use it on systems without permission!
⭐ Support the Project

🔹 Found SentinelForge useful? Give it a ⭐ on GitHub!
🔹 Follow me for updates & more security tools.

📌 Author: Your Name
🔗 GitHub: Your GitHub Profile
🚀 Let’s build the future of security together!
