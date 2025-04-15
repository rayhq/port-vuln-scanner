import nmap
import socket
import requests
import csv
import json
from datetime import datetime

results = []  # Global list to hold scan results

def get_target_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        print(f"❌ Could not resolve: {domain}")
        return None

def search_cve(keyword):
    url = f"https://cve.circl.lu/api/search/{keyword}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            results = response.json().get("data", [])
            return results[:3]  # Return top 3
    except Exception as e:
        print(f"    ⚠️ CVE lookup error: {e}")
    return []

def grab_banner(ip, port, timeout=3):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            banner = s.recv(1024).decode(errors="ignore").strip()
            return banner if banner else "No banner received"
    except Exception as e:
        return f"Banner grab failed"

def scan_target(target):
    print(f"\n🔍 Scanning {target}...\n")
    scanner = nmap.PortScanner()
    scanner.scan(hosts=target, arguments='-sS -sV -T4')

    for host in scanner.all_hosts():
        hostname = scanner[host].hostname()
        state = scanner[host].state()

        protocols = scanner[host].all_protocols()
        if not protocols:
            print("⚠️ No open ports found.")
            continue

        for proto in protocols:
            ports = scanner[host][proto].keys()

            for port in sorted(ports):
                port_data = scanner[host][proto][port]
                state = port_data['state']
                name = port_data['name']
                product = port_data.get('product', '')
                version = port_data.get('version', '')
                cve_data = []

                # 🔍 Banner grabbing
                banner = grab_banner(host, port)
                print(f"  ▶ Port {port}: {state} | {name} {product} {version}")
                print(f"    🧠 Banner: {banner}")

                # Custom vuln check
                if 'ftp' in name and 'vsftpd' in product and '2.3.4' in version:
                    print("    🚨 Vulnerable: vsftpd 2.3.4 backdoor")

                # CVE Integration
                if product:
                    keyword = f"{product} {version}".strip()
                    cve_data = search_cve(keyword)
                    if cve_data:
                        print(f"    🛡️  Found {len(cve_data)} CVEs")
                        for cve in cve_data:
                            print(f"     🔴 {cve['id']} - {cve['summary'][:100]}...")
                    else:
                        print("    ✅ No known CVEs")

                # Save result to global list
                results.append({
                    "host": host,
                    "hostname": hostname,
                    "port": port,
                    "state": state,
                    "service": name,
                    "product": product,
                    "version": version,
                    "banner": banner,
                    "cves": [{"id": c['id'], "summary": c['summary']} for c in cve_data]
                })

def export_to_csv(filename="scan_report.csv"):
    with open(filename, "w", newline='') as csvfile:
        fieldnames = ["host", "hostname", "port", "state", "service", "product", "version", "banner", "cve_id", "cve_summary"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for entry in results:
            if entry["cves"]:
                for cve in entry["cves"]:
                    writer.writerow({
                        **{k: entry[k] for k in fieldnames if k not in ["cve_id", "cve_summary"]},
                        "cve_id": cve["id"],
                        "cve_summary": cve["summary"]
                    })
            else:
                writer.writerow({
                    **{k: entry[k] for k in fieldnames if k not in ["cve_id", "cve_summary"]},
                    "cve_id": "None",
                    "cve_summary": "No known vulnerabilities"
                })
    print(f"\n📁 CSV report saved as: {filename}")

def export_to_json(filename="scan_report.json"):
    with open(filename, "w") as jsonfile:
        json.dump(results, jsonfile, indent=4)
    print(f"📁 JSON report saved as: {filename}")

if __name__ == "__main__":
    target = input("Enter domain or IP: ")
    ip = get_target_ip(target)

    if ip:
        scan_target(ip)

        # Export the results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        export_to_csv(f"scan_report_{timestamp}.csv")
        export_to_json(f"scan_report_{timestamp}.json")
