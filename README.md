IP Recon Tools

This repository contains two Python-based tools for network reconnaissance:

    Passive IP Recon Tool (passive_ip_recon.py)

    Active IP Recon Tool (active_ip_recon.py)

Both tools generate reports detailing the information gathered from the target IP addresses.
Overview
Passive IP Recon Tool

The Passive IP Recon tool is designed to gather information about a target IP address without sending active probes that could trigger security alerts. It collects data such as:

    Reverse DNS Lookup: Retrieves the hostname associated with the IP.

    Geolocation Information: Uses the ipinfo.io API to determine the location of the IP.

    IP Reputation: Provides a stub for abuse reputation checks (using AbuseIPDB; an API key is required for live usage).

    WHOIS/RDAP Information: Obtains registration details via a modern RDAP lookup.

This tool supports concurrent investigations for multiple IP addresses (up to 5 at a time) and generates both JSON and text reports.
Active IP Recon Tool

The Active IP Recon tool actively scans a target IP address and retrieves more detailed network information. Features include:

    Port Scanning: Uses native Python sockets and (optionally) Nmap (if installed) to scan common or specified ports.

    Banner Grabbing & Service Detection: Attempts to identify services by grabbing banners from open ports.

    HTTP/HTTPS Analysis: Performs HTTP server fingerprinting (status codes, headers, and page title) for servers running on port 80 and 443.

    SSL/TLS Certificate Analysis: Examines the certificate details for HTTPS services.

    Vulnerability Checks: Optionally uses Nmap scripts (e.g., "vulners") for vulnerability assessments if available.

    Scanning Intensity Levels: Allows selection of scanning intensity (levels 1–5) to control the depth and speed of the scan.

Important: Since active scanning can be invasive, the tool includes a disclaimer and a confirmation prompt to ensure you have permission to scan the target IP addresses.

This tool also saves its results into both JSON files and a neatly formatted text report.
Prerequisites

    Python: Version 3.x is required.

    Python Packages: Make sure to install necessary libraries:

    pip install requests
    pip install beautifulsoup4

    Nmap (Optional for Active Recon Tool):
    For enhanced active scanning, installing Nmap is recommended and it must be available in your system PATH.

    API Keys (Optional):
    To enable real-time lookups, such as for AbuseIPDB and Shodan, set up the respective API keys by exporting them as environment variables (e.g., ABUSEIPDB_API_KEY and SHODAN_API_KEY).

Installation

Clone the repository and navigate to its directory:

git clone https://github.com/pixelbrow720/ip_toolkit.git
cd ip_toolkit

Ensure that the repository structure includes:

.
├── passive_ip_recon.py
├── active_ip_recon.py
└── reports
    ├── ip_recon
    └── active_recon

(The reports directories are used by the tools to save output files.)
Usage
Passive IP Recon Tool
Command Syntax

python passive_ip_recon.py <ip1> [ip2] [ip3] [ip4] [ip5] [--parallel] [--output OUTPUT_FILE] [--rate-limit RATE]

Parameters

    <ip1> [ip2] ...: One or more target IP addresses (maximum 5).

    --parallel: Run investigations concurrently.

    --output OUTPUT_FILE: Specify a custom output filename for the JSON report.

    --rate-limit RATE: Set a delay (in seconds) between API requests (default is 1.0 second).

Example

python passive_ip_recon.py 8.8.8.8 1.1.1.1 --parallel --rate-limit 0.5

Active IP Recon Tool
Command Syntax

python active_ip_recon.py [--ports PORTS] [--intensity {1,2,3,4,5}] [--parallel] [--output OUTPUT_FILE] [--timeout TIMEOUT] ip1 [ip2] [ip3] ...

Parameters

    ip1 [ip2] ...: Target IP addresses to scan (up to 5).

    --ports PORTS: Ports to scan specified in Nmap format (e.g., "22,80,443" or "1-1000"). If not provided, default port lists will be used according to the scanning intensity.

    --intensity {1,2,3,4,5}: Sets the scanning intensity (1 is least invasive; 5 is most comprehensive). Default is 3.

    --parallel: Executes the scan concurrently across multiple IPs.

    --output OUTPUT_FILE: Custom filename for the JSON results.

    --timeout TIMEOUT: Connection timeout (in seconds), default is 5.

Example

python active_ip_recon.py 192.168.1.1 --ports "22,80,443" --intensity 3 --parallel --timeout 5

    Note: When using an intensity level of 4 or higher, the tool will display warnings and prompt for user confirmation due to the higher invasiveness of such scans.

Output

    JSON Report:
    Each tool saves a detailed JSON file containing the full results of the investigation.

    Text Report:
    A human-readable text report is generated summarizing the gathered information.
    Both reports are stored in the respective reports/ip_recon or reports/active_recon directories.

Disclaimer

WARNING:
The Active IP Recon Tool performs active network scanning that might trigger security alerts or be considered intrusive. Ensure you have explicit permission to scan the target IP addresses before using this tool. Unauthorized scanning can be illegal and unethical. Use these tools responsibly.
Contributing

Contributions, bug reports, and feature requests are welcome!
Feel free to fork the repository, make improvements, and submit a pull request.
License

MIT License

This README provides an overview of both IP recon tools, along with detailed instructions on how to install and use them. Enjoy exploring and enhancing your network reconnaissance skills responsibly
