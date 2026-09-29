SentinelForge

SentinelForge is a modular security assessment framework for authorized security research and defensive security testing.

It provides a command-line workflow for reconnaissance, vulnerability assessment, exploit validation, session management, finding correlation, reporting, and optional external integrations.

«Current release: "1.0.0"»

Features

- Modular security scanning architecture
- Passive reconnaissance and information gathering
- Active vulnerability scanning
- Exploit validation modules
- DNS, HTTP, SSL, web, OSINT, and network plugins
- Configurable scan profiles
- Session management and resumable scan workflows
- Finding correlation and risk scoring
- HTML and JSON reporting
- Evidence collection
- Configurable redirects, timeouts, retries, threading, and rate limits
- Secure TLS verification by default
- Optional Shodan host-intelligence integration
- Optional Neo4j graph-based scan persistence
- CLI diagnostics with "sf doctor"
- Docker support
- Automated test suite

Quick start

Clone the repository:

git clone https://github.com/Ayan2238/sentinelfroge.git
cd sentinelfroge/sentinelforge

Create a virtual environment:

python -m venv .venv
source .venv/bin/activate

Install the core package:

pip install -e .

For development dependencies:

pip install -e ".[dev]"

For optional integrations and DNS support:

pip install -e ".[full]"

Verify the installation:

sf --version
sf doctor

Run a scan against an authorized target:

sf scan example.com

Configuration

SentinelForge uses YAML configuration with environment-variable overrides.

The main configuration file is:

sentinelforge/configs/config.yaml

A safe environment template is provided:

cp .env.example .env

Credentials should be supplied through local configuration or environment variables and should never be committed to the repository.

Environment variables

Examples include:

SF_LOG_LEVEL
SF_OUTPUT_DIR
SF_MAX_THREADS
SF_TIMEOUT
SF_PROXY
SF_SHODAN_API_KEY
SF_NEO4J_URI
SF_NEO4J_USER
SF_NEO4J_PASSWORD
SF_NEO4J_DATABASE
SF_PROFILE

Optional integrations

Shodan

SentinelForge can optionally use Shodan for host intelligence and external service information.

Configure a local Shodan API key through:

SF_SHODAN_API_KEY

The integration remains optional and does not prevent the core scanner from operating when Shodan is unavailable or unconfigured.

Neo4j

SentinelForge can optionally persist completed scan sessions to Neo4j.

Neo4j support is installed through the optional dependency set:

pip install -e ".[neo4j]"

or:

pip install -e ".[full]"

Configure the integration using:

SF_NEO4J_URI
SF_NEO4J_USER
SF_NEO4J_PASSWORD
SF_NEO4J_DATABASE

Neo4j persistence is explicitly disabled by default. When enabled, completed sessions can be represented as a graph containing scan sessions, targets, and findings.

The Neo4j integration is designed so that database availability or persistence failures do not prevent the local scan and reporting workflow from completing.

Reports

By default, SentinelForge can generate:

- HTML reports
- JSON reports

Reports are written to the configured output directory.

The reporting system includes scan metadata, findings, severity information, evidence, recommendations, and other available analysis data.

Repository layout

sentinelfroge/
└── sentinelforge/
    ├── sentinelforge/       # Python package and CLI
    ├── tests/               # Automated tests
    ├── configs/             # Configuration and scan profiles
    ├── docs/                # Documentation
    ├── pyproject.toml       # Package metadata and dependencies
    └── Dockerfile           # Container build

Architecture

SentinelForge is organized around separate components for:

CLI
 │
 ├── Configuration
 ├── Target management
 ├── Session management
 ├── Module discovery
 ├── Plugin discovery
 │
 ├── Reconnaissance
 ├── Vulnerability scanning
 ├── Exploit validation
 │
 ├── Finding correlation
 ├── Risk analysis
 ├── Reporting
 │
 ├── Shodan integration      (optional)
 └── Neo4j persistence       (optional)

The architecture is designed to keep the core scanning workflow usable without requiring external services.

Testing

Run the test suite with:

pytest -q

The project is developed with automated testing covering core functionality, configuration, scanning behavior, integrations, and security-sensitive behavior.

Docker

A Dockerfile is included for containerized usage.

Build the image:

docker build -t sentinelforge .

Refer to the project documentation for the supported container workflow and configuration options.

Documentation

Additional documentation is available in:

sentinelforge/README.md
sentinelforge/docs/

These resources contain additional information about:

- Installation
- Configuration
- Architecture
- Scanning
- Plugins
- Reporting
- Development

Responsible use

SentinelForge is intended for authorized security assessment, defensive security testing, and security research.

Only scan systems, networks, applications, and infrastructure that you own or have explicit permission to assess.

Do not use SentinelForge to access, disrupt, exploit, or test systems without authorization.

You are responsible for complying with all applicable laws, regulations, contracts, and security policies when using the software.

Security

Do not commit:

- API keys
- Passwords
- Private keys
- Access tokens
- Personal credentials
- Private configuration files
- Generated reports containing sensitive information

Use environment variables or local configuration for credentials.

If you discover a security issue in SentinelForge, please report it responsibly rather than publicly disclosing sensitive details before the issue can be addressed.

License

See the repository's license file for the applicable licensing terms.
