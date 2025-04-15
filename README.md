# Port and Vulnerability Scanner 🔍

This Python-based port scanner tool scans a target (domain or IP) for open ports, grabs banners, and performs vulnerability checks by referencing Common Vulnerabilities and Exposures (CVEs). The tool utilizes Nmap for port scanning, Python's `socket` library for banner grabbing, and integrates CVE search from the CIRCL API to check for known vulnerabilities in services found on the target.

## Table of Contents
1. [Features](#features)
2. [Requirements](#requirements)
3. [Installation](#installation)
4. [Usage](#usage)
5. [Configuration](#configuration)
6. [Output](#output)
7. [Example](#example)
8. [Contributing](#contributing)
9. [License](#license)

## Features
- **Port Scanning**: Scans the target for open ports using Nmap with various options like `-sS` (SYN scan), `-sV` (service version detection), and `-T4` (timing for faster scans).
- **Banner Grabbing**: Retrieves service banners for each open port to gather more information about the services running.
- **Vulnerability Check**: Searches for known CVEs related to detected services and versions using the CIRCL CVE API. The tool provides alerts for specific vulnerabilities like the `vsftpd 2.3.4 backdoor`.
- **CSV & JSON Reports**: Generates detailed reports in CSV and JSON formats that list discovered ports, services, banners, and associated CVEs.
- **Custom Vulnerability Checks**: In addition to CVE search, the script can be customized to look for specific vulnerabilities or backdoors in services.

## Requirements
- **Python 3.x**: Ensure you are running Python 3.x. It is recommended to create a virtual environment to keep dependencies isolated.
- **Nmap**: Used for port scanning. Make sure Nmap is installed on your system and accessible from the command line.
- **Required Python Libraries**:
    - `nmap`: Python library for interacting with Nmap.
    - `requests`: Used to send HTTP requests for CVE lookup.

## Installation

### 1. Clone the Repository
Clone the project to your local machine:

```bash
git clone https://github.com/yourusername/port-vuln-scanner.git
cd port-vuln-scanner
```
### 2. Install Dependencies
Create a virtual environment (optional but recommended) and install the required Python libraries:
```bash
python -m venv venv
source venv/bin/activate   # On Windows, use `venv\Scripts\activate`
pip install -r requirements.txt
```
### 3. Install Nmap
- To use the Nmap functionality, you need to install [Nmap](https://nmap.org/download) :
- Windows: Nmap download for Windows
- Linux: Use your package manager to install it (e.g., sudo apt install nmap).
- macOS: Use Homebrew (brew install nmap).
## Usage
- Once you've installed all dependencies and Nmap, you can run the scanner with the following command:
  ```bash
  python scanner.py
  ```
You will be prompted to enter the target domain or IP address. The script will:
- Perform port scanning with Nmap.
- Grab banners for the discovered services.
- Check for known CVEs related to those services using the CIRCL CVE API.
- Generate a CSV and a JSON report containing the results.
  ### Example Command:
  ```bash
  Enter domain or IP: example.com
  ```
### Sample Output:
```bash
🔍 Scanning example.com...

  ▶ Port 80: open | http  Apache httpd 2.4.46
    🧠 Banner: Apache/2.4.46 (Ubuntu)
    🛡️ Found 2 CVEs
     🔴 CVE-2020-9490 - Apache HTTPD 2.4.46 vulnerability...
     🔴 CVE-2020-11984 - Apache HTTPD mod_proxy vulnerability...

  ▶ Port 443: open | https  Apache httpd 2.4.46
    🧠 Banner: Apache/2.4.46 (Ubuntu)
    ✅ No known CVEs
```
## Configuration
Scan Options
The script currently uses the following Nmap options:
- -sS: SYN scan (stealth scan).
- -sV: Service version detection.
- -T4: Timing template for faster scans (T4 is recommended for most cases).
If you need to change the scanning options, modify the scan_target() function in the scanner.py file.
### Custom CVE Lookup
You can also customize the CVE lookup by changing the search_cve() function to look for specific keywords or integrate with other CVE databases.
## Output
The script generates two types of reports:
- CSV Report: Lists the ports, services, banners, and CVEs in CSV format.
- JSON Report: Provides detailed results in a structured JSON format.
Both reports are saved with a timestamp, e.g., scan_report_20230415_153045.csv.
### Example CSV output:
```bash
host,hostname,port,state,service,product,version,banner,cve_id,cve_summary
192.168.1.1,localhost,80,open,http,Apache,httpd 2.4.46,Apache/2.4.46 (Ubuntu),CVE-2020-9490,"Apache HTTPD 2.4.46 vulnerability"
192.168.1.1,localhost,443,open,https,Apache,httpd 2.4.46,Apache/2.4.46 (Ubuntu),None,"No known vulnerabilities"
```
### Example JSON output:
```bash
[
    {
        "host": "192.168.1.1",
        "hostname": "localhost",
        "port": 80,
        "state": "open",
        "service": "http",
        "product": "Apache",
        "version": "httpd 2.4.46",
        "banner": "Apache/2.4.46 (Ubuntu)",
        "cves": [
            {
                "id": "CVE-2020-9490",
                "summary": "Apache HTTPD 2.4.46 vulnerability..."
            }
        ]
    },
    {
        "host": "192.168.1.1",
        "hostname": "localhost",
        "port": 443,
        "state": "open",
        "service": "https",
        "product": "Apache",
        "version": "httpd 2.4.46",
        "banner": "Apache/2.4.46 (Ubuntu)",
        "cves": []
    }
]
```
## Example
Here’s an example of running the scanner on a public IP:
python scanner.py

```bash
Enter domain or IP: example.com
🔍 Scanning example.com...
  ▶ Port 80: open | http Apache httpd 2.4.46
    🧠 Banner: Apache/2.4.46 (Ubuntu)
    🛡️ Found 1 CVE
     🔴 CVE-2020-9490 - Apache HTTPD 2.4.46 vulnerability...
```
### Contributing
We welcome contributions to improve the tool! If you find a bug or have an idea for a feature, feel free to open an issue or submit a pull request.

## How to Contribute:
- Fork the repository
- Clone your fork to your local machine
- Create a new branch (git checkout -b feature-branch)
- Make your changes
- Commit your changes (git commit -m "Add feature")
- Push to your fork (git push origin feature-branch)
- Open a pull request to the main repository

### License

This project is licensed under the MIT License - see the [LICENSE](./LICENSE) file for details.



