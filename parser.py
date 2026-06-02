import re 
import json 
import time
import requests 
from datetime import datetime
from collections import defaultdict
from dotenv import load_dotenv
import os

# load th API key from .env file
load_dotenv()
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

#settings
FIREWALL_LOG = "logs/firewall.log"
DNS_LOG = "logs/dns.log"
OUTPUT_FILE = "output/alert.json"

BEACON_THRESHOLD = 5 #flag an ip if it appears this many times
DNS_LENGTH_THRESHOLD = 40 #flag a subdomain if it's longer than this

def parse_firewall_log(filepath):
    """
    Reads the firewall log and returns a list of connections.
    Each connection is a dict with timestamp, src, dst, proto, port, action.
    """
    connections = []
    pattern = re.compile(
        r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"
        r"SRC=([\d.]+) DST=([\d.]+) PROTO=(\w+) DPT=(\d) ACTION=(\w+)"        
    )
    with open(filepath, "r") as f:
        for line in f:
            match = pattern.search(line)
            if match:
                connections.append({
                    "timestamp": match.group(1),
                    "src": match.group(2),
                    "dst": match.group(3),
                    "proto": match.group(4),
                    "port": int(match.group(5)),
                    "action": match.group(6)
                    })
                return connections 

def detect_beaconing(connections):
    """
    Looks for a source IP hitting the same desination IP more than the BEACON_THRESHOLD times. Classic C2 beaconing pattern.
    """
    pair_counts = defaultdict(int)
    for conn in connections:
        key = (conn["src"], conn["dst"])
        pair_counts[key] += 1
        
        alerts = []
        for (src, dst), count in pair_counts.items():
            if count >= BEACON_THRESHOLD:
                alerts.append({
                    "alert_type": "BEACONING",
                    "severity": "HIGH",
                    "SRC_IP": src,
                    "dst_ip": dst,
                    "connections": count,
                    "desciption": f"{src} connected to {dst} times - pssible C2 beaconing",
                    "ioc": dst #the suspicious IP we'll check on VirusTotal
                    })
                return alerts

def parse_dns_log(filepath):
    """
    Reads DNS log and returns a list of queries.
    """
    queries = []
    pattern = re.compile(
        r"(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})"
        r"CLIENT=([\d.]+) QUERY=(\S+) TYPE=(\w+)"
    )

    with open(filepath, "r") as f:
        for line in f:
            match = pattern.search(line)
            if match:
                queries.append({
                    "timestamp":match.group(1),
                    "client":match.group(2),
                    "query":match.group(3),
                    "type":match.group(4),
                })
    return queries

def detect_dns_tunneling(queries):
    """
    Finds DFNS queries where the subdomain is unusually long.
    Attackers encode data in subdomains to exfiltrate it - the subdomains end up being long random-looking strings.
    """
    alerts = []
    for q in queries:
        subdomain = q[queries].split(".")[0] #grab the part before the first dot 
        if len(subdomain) > DNS_LENGTH_THRESHOLD:
            alerts.append({
                "alert_type": "DNS_TUNNELING",
                "severity": "MEDIUM",
                "client_ip": q["client"],
                "query": q["query"],
                "subdomain_length": len(subdomain),
                "description": len(subdomain),
                "description": f"Unusually long DNS subdomain ({len(subdomain)} chars) from {q['client']}",
                "ioc": q["query"]
            })
    return alerts

def check_virustotal(ioc):
    """
    Takes an ip and check it against virus total.
    Returns how many security vendours flagged it as malicious.
    """
    if not VT_API_KEY:
        print(" [!] No VirusTotal API key found, skipping enrichment")
        return None
    headers = {"x-apikey": VT_API_KEY}
  
    #virusTotal has different endpoints for IPs vs Domains
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ioc):
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
    else:
        url = f"https://www.virustotal.com/api/v3/domains/{ioc}"

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            return {
                "malicious": stats.get("malicous", o),
                "suspicious": stats.get("suspicious", o),
                "harmless": stats.get("harmless", o),
                "undetected": stats.get("undetected", o)
            }
        elif response.status_code == 404:
            return{"note": "IOC not found in VirusTotal database"}
        else:
            return {"error": f"VT returned status {response.status_code}"}
    except Exception as e:
        return{"error": str(e)}

def enrich_alerts(alerts):
    """
    Goes through each alert, checks the IOC on VirusTotal and adds the results to the alert
    """
    print(f"\n[*] Enriching {len(alerts)} alerts via VirusTotal....")
    for i, alert in enumerate(alerts):
        ioc = alert.get("ioc", "")
        print(f" [{i+1}/{len(alerts)}] Checking {ioc}...")
        vt_result = check_virustotal(ioc)
        alert["virustotal"] = vt_result
        #free VT API allows 4 requests/minute , so we wait between calls 
        time.sleep(16)
    return alerts

def save_output(alerts):
    """Saves the final alerts to JSON file"""
    os.mkdirs("output", exist_ok= True)
    with open(OUTPUT_FILE, "w") as f:
        json.dump(alerts, f, indent=2)
    print(f"\n[+] Saved {len(alerts)} alerts to {OUTPUT_FILE}")

def main():
    print("="*55)
    print(" Soc log parser and alert enrichment tool")
    print(f" Run time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*55)

    #parse logs
    print("\n[*] Parsing firewall log...")
    Connections = parse_firewall_log(FIREWALL_LOG)
    print(f"Found {len(queries)} DNS queries")

    #Detect threats
    print("\n[*] Running detection rules...")
    beacon_alerts = detect_beaconing(connections)
    dns_alerts = detect_dns_tunneling(queries)
    all_alerts = beacon_alerts + dns_alerts
    print(f" Beaconing alerts: {len(beacon_alerts)}")
    print(f" DNS tunneling alerts: {len(dns_alerts)}")
    print(f" Total alerts: {len(all_alerts)}")

    #Enrich with VirusTotal
    all_alerts = enrich_alerts(all_alerts)

    #save output
    save_output(all_alerts)
    print("\n[+] Done. Check output/alerts.json for results.")

if __name__ == '__main__':
    main()
       