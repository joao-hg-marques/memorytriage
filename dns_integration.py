
import os
import re
import requests
from html import escape

ABUSEIPDB_API_KEY = "c5f5af38ca7df2ec0557db4716d381f48a92377d32ea03291fcd7fd2d460034db357fa8260626241"  # Replace this with the actual key

def parse_dns_file(dns_path):
    entries = []
    if os.path.exists(dns_path):
        with open(dns_path, "r", encoding="utf-8") as f:
            for line in f:
                # Example: 0005 01fa58b1afe0 A 1410 boot-relays.net.anydesk.com 92.223.88.232
                parts = line.strip().split()
                if len(parts) >= 6:
                    record_type = parts[2]
                    if record_type in {"A", "AAAA"}:
                        domain = parts[4]
                        ip = parts[5]
                        entries.append((domain, ip))
    return entries

def check_abuse_ip(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Accept": "application/json",
        "Key": ABUSEIPDB_API_KEY
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }
    try:
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            data = response.json().get("data", {})
            return {
                "ip": ip,
                "abuseScore": data.get("abuseConfidenceScore", 0),
                "country": data.get("countryCode", "N/A"),
                "domain": data.get("domain", "N/A"),
                "usageType": data.get("usageType", "N/A"),
                "isp": data.get("isp", "N/A")
            }
        else:
            return {"ip": ip, "error": f"API error {response.status_code}"}
    except Exception as e:
        return {"ip": ip, "error": str(e)}

def generate_dns_section(dns_path):
    entries = parse_dns_file(dns_path)
    section = "<h2>DNS Resolution & AbuseIPDB Check</h2><ul>"
    seen_ips = set()
    for domain, ip in entries:
        if ip in seen_ips:
            continue
        seen_ips.add(ip)

        abuse_info = check_abuse_ip(ip)
        abuse_score = abuse_info.get("abuseScore", 0)
        risk_color = "red" if abuse_score >= 50 else ("orange" if abuse_score >= 20 else "green")
        section += f"<li><b>{escape(domain)}</b> → {ip} <br>"                    f"&nbsp;&nbsp;↳ Abuse Score: <span style='color:{risk_color}'>{abuse_score}</span><br>"                    f"&nbsp;&nbsp;↳ Country: {escape(abuse_info.get('country', 'N/A'))}<br>"                    f"&nbsp;&nbsp;↳ ISP: {escape(abuse_info.get('isp', 'N/A'))}<br>"                    f"&nbsp;&nbsp;↳ Usage: {escape(abuse_info.get('usageType', 'N/A'))}<br>"                    f"&nbsp;&nbsp;↳ Domain (from AbuseIPDB): {escape(abuse_info.get('domain', 'N/A'))}</li>"
    section += "</ul>"
    return section
