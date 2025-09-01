"""
Enhanced Vulnerability Assessment Tool
Combines Nmap scanning with network traffic analysis using Scapy
"""
from __future__ import annotations
import requests
import time
import os, re
import threading
from collections import defaultdict, Counter
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import socket


SCAN_MODE = "balanced"  # Default scan mode
FAST_NMAP_ARGS = "-T4 -sV -sC"  # Added vuln scanning
BALANCED_NMAP_ARGS = "-T4 -A -sV -sC -O --script vuln"  # Enhanced vuln scanning
THOROUGH_NMAP_ARGS = "-T4 -A -sS -sV -sC -O -p-"  # Comprehensive
TOP_PORTS_FAST = "1-1000"
TOP_PORTS_THOROUGH = "1-10000"  # More reasonable than full range


API_KEY = os.getenv("VULNERS_API_KEY", "").strip()
USE_VULNERS = bool(API_KEY)


def get_script_args(mode: str = "balanced"):
    """Get appropriate script arguments based on scan mode"""
    base_scripts = []

    if USE_VULNERS:
        base_scripts.append("vulners")
        script_args = f"vulners.apikey={API_KEY}"
    else:
        base_scripts.extend(["vuln"])
        script_args = ""

    if mode == "thorough":
        base_scripts.extend([""])

    return ",".join(base_scripts), script_args

import nmap  # python‑nmap
try:
    from scapy.all import sniff, IP, TCP, UDP, Raw, DNS, DNSQR, ARP
    from scapy.layers.tls.all import TLS
    SCAPY_AVAILABLE = True
except ImportError:
    print("[WARNING] Scapy not available. Install with: pip install scapy")
    SCAPY_AVAILABLE = False


SUSPICIOUS_PORTS = {21, 23, 53, 69, 79, 110, 143, 161, 389, 512, 513, 514, 1433, 3306}
PLAINTEXT_PROTOCOLS = {21: 'FTP', 23: 'Telnet', 53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP', 389: 'LDAP'}


ID_RE = re.compile(r"\b(?:CVE-\d{4}-\d{4,7}|GHSA-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4})\b")
CVSS_RE = re.compile(r"CVSS[: ]\s*(\d+\.\d+)")
VULN_RE = re.compile(r"(?i)\b(?:VULNERABLE|EXPLOIT|BACKDOOR|MALWARE|TROJAN|ROOTKIT)\b.*")


VULN_PATTERNS = [
    re.compile(r"(?i).*vulnerable.*", re.MULTILINE),
    re.compile(r"(?i).*exploit.*available.*", re.MULTILINE),
    re.compile(r"(?i).*weak.*password.*", re.MULTILINE),
    re.compile(r"(?i).*default.*credential.*", re.MULTILINE),
    re.compile(r"(?i).*unpatched.*", re.MULTILINE),
    re.compile(r"(?i).*outdated.*version.*", re.MULTILINE)
]


class TrafficAnalyzer:
    def __init__(self, target_network: str):
        self.target_network = target_network
        self.findings = []
        self.packet_count = 0
        self.connection_stats = defaultdict(int)
        self.suspicious_traffic = []
        self.credentials_found = []
        self.dns_queries = Counter()
        self.unencrypted_services = set()
        self.stop_capture = False
        self.captured_packets = []

    def packet_handler(self, pkt):
        self.packet_count += 1
        self.captured_packets.append(pkt)

        if TCP in pkt and pkt[TCP].dport in [4444, 1337, 31337]:
            self.findings.append({...})

        self._analyze_tcp_traffic(pkt)
        self._analyze_udp_traffic(pkt)
        self._analyze_dns_traffic(pkt)
        self._analyze_suspicious_patterns(pkt)

    def _analyze_traffic(self, timeout: int = 60) -> list:
        findings = []

        try:
            def packet_handler(self, pkt):
                self.packet_count += 1
                self.captured_packets.append(pkt)

                # Example check: suspicious ports
                if TCP in pkt and pkt[TCP].dport in [4444, 1337, 31337]:
                    findings.append({
                        "type": "network_traffic",
                        "category": "Suspicious Port",
                        "host": pkt[IP].dst if IP in pkt else "Unknown",
                        "port": pkt[TCP].dport,
                        "service": "Unknown",
                        "severity": "Medium",
                        "description": f"Suspicious traffic to port {pkt[TCP].dport}"
                    })

                self._analyze_tcp_traffic(pkt)
                self._analyze_udp_traffic(pkt)
                self._analyze_dns_traffic(pkt)
                self._analyze_suspicious_patterns(pkt)

            sniff(filter="ip", prn=self.packet_handler, store=False, iface="YOUR_INTERFACE")

        except Exception as e:
            print(f"[!] Traffic analysis failed: {e}")

        return findings

    def _is_target_ip(self, ip: str) -> bool:
        """Check if IP is in target network range"""

        target_base = self.target_network.split('/')[0] if '/' in self.target_network else self.target_network
        target_octets = target_base.split('.')[:3]
        ip_octets = ip.split('.')[:3]
        return target_octets == ip_octets

    def _analyze_tcp_traffic(self, packet):
        """Analyze TCP traffic for vulnerabilities"""
        if not packet.haslayer(TCP):
            return

        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport


        connection = f"{packet[IP].src}:{src_port} -> {packet[IP].dst}:{dst_port}"
        self.connection_stats[connection] += 1


        if dst_port in PLAINTEXT_PROTOCOLS:
            self.unencrypted_services.add((packet[IP].dst, dst_port, PLAINTEXT_PROTOCOLS[dst_port]))


        if packet.haslayer(Raw):
            payload = packet[Raw].load
            self._check_for_credentials(payload, packet[IP].src, packet[IP].dst, dst_port)


        if dst_port in SUSPICIOUS_PORTS:
            self.suspicious_traffic.append({
                'type': 'suspicious_port',
                'src': packet[IP].src,
                'dst': packet[IP].dst,
                'port': dst_port,
                'protocol': 'TCP',
                'timestamp': datetime.now()
            })

    def _analyze_udp_traffic(self, packet):
        """Analyze UDP traffic"""
        if not packet.haslayer(UDP):
            return

        dst_port = packet[UDP].dport


        if dst_port == 161:
            self.suspicious_traffic.append({
                'type': 'snmp_traffic',
                'src': packet[IP].src,
                'dst': packet[IP].dst,
                'port': dst_port,
                'protocol': 'UDP',
                'timestamp': datetime.now()
            })

    def _analyze_dns_traffic(self, packet):
        """Analyze DNS queries for suspicious domains"""
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            query = packet[DNSQR].qname.decode('utf-8').rstrip('.')
            self.dns_queries[query] += 1

            # Flag suspicious TLDs or patterns
            suspicious_tlds = ['.tk', '.ml', '.cf', '.ga', '.onion']
            if any(query.endswith(tld) for tld in suspicious_tlds):
                self.suspicious_traffic.append({
                    'type': 'suspicious_dns',
                    'query': query,
                    'src': packet[IP].src,
                    'timestamp': datetime.now()
                })

    def _check_for_credentials(self, payload: bytes, src_ip: str, dst_ip: str, port: int):
        """Look for plaintext credentials in packet payload"""
        try:
            text = payload.decode('utf-8', errors='ignore').lower()

            # Common credential patterns
            cred_patterns = [
                r'user(?:name)?[:\s=]+([^\s\r\n]+)',
                r'pass(?:word)?[:\s=]+([^\s\r\n]+)',
                r'login[:\s=]+([^\s\r\n]+)',
                r'auth[:\s=]+([^\s\r\n]+)'
            ]

            for pattern in cred_patterns:
                matches = re.findall(pattern, text)
                if matches:
                    self.credentials_found.append({
                        'src': src_ip,
                        'dst': dst_ip,
                        'port': port,
                        'credential_type': pattern,
                        'timestamp': datetime.now()
                    })
        except:
            pass

    def _analyze_suspicious_patterns(self, packet):
        """Detect various suspicious network patterns"""

        if packet.haslayer(TCP):
            # SYN scan detection
            if packet[TCP].flags == 2:  # SYN flag
                self.connection_stats[f"syn_scan_{packet[IP].src}"] += 1


        if packet.haslayer(ARP):
            if packet[ARP].op == 2:  # ARP reply
                self.suspicious_traffic.append({
                    'type': 'arp_reply',
                    'src_mac': packet[ARP].hwsrc,
                    'src_ip': packet[ARP].psrc,
                    'dst_ip': packet[ARP].pdst,
                    'timestamp': datetime.now()
                })

    def generate_findings(self) -> List[Dict[str, Any]]:
        """Generate vulnerability findings from traffic analysis"""
        findings = []


        reported = set()


        for ip, port, service in self.unencrypted_services:
            findings.append({
                'type': 'network_traffic',
                'category': 'unencrypted_service',
                'host': ip,
                'port': port,
                'service': service,
                'severity': 'Medium',
                'description': f'{service} service detected using unencrypted communication',
                'cvss': 5.0
            })
            reported.add((ip, port))


        if self.credentials_found:
            for cred in self.credentials_found:
                findings.append({
                    'type': 'network_traffic',
                    'category': 'credential_exposure',
                    'host': cred['dst'],
                    'port': cred['port'],
                    'severity': 'High',
                    'description': 'Potential credentials detected in plaintext traffic',
                    'cvss': 7.5
                })
                reported.add((cred['dst'], cred['port']))


        suspicious_counts = Counter([s['type'] for s in self.suspicious_traffic])
        for traffic_type, count in suspicious_counts.items():
            if count > 5:  # Threshold for suspicious activity
                findings.append({
                    'type': 'network_traffic',
                    'category': 'suspicious_activity',
                    'description': f'High volume of {traffic_type} detected ({count} instances)',
                    'severity': 'Medium',
                    'cvss': 4.0
                })


        for pkt in self.captured_packets:
            ip_layer = pkt.getlayer(IP)
            if not ip_layer:
                continue  # Skip non-IP packets

            proto = "TCP" if pkt.haslayer(TCP) else "UDP" if pkt.haslayer(UDP) else "Other"
            host = ip_layer.dst
            dport = getattr(pkt, 'dport', None)
            sport = getattr(pkt, 'sport', None)

            if not dport:
                continue

            if (host, dport) in reported:
                continue  # Skip already reported packets

            try:
                service = socket.getservbyport(dport)
            except:
                service = ""

            findings.append({
                "type": "network_traffic",
                "category": proto,
                "host": host,
                "port": dport,
                "service": service,
                "severity": "Info",
                "description": f"Observed {proto} traffic to port {dport} on {host}"
            })


        findings.append({
            'type': 'network_traffic',
            'category': 'summary',
            'host': 'N/A',
            'port': 'N/A',
            'severity': 'Info',
            'description': f"Captured and analyzed {len(self.captured_packets)} packets."
        })

        return findings


def _extract_cves(text: str) -> list[dict]:
    """Extract CVEs with enhanced pattern matching"""
    out = []
    for line in text.splitlines():
        if (m := ID_RE.search(line)):
            score = None
            if (s := CVSS_RE.search(line)):
                try:
                    score = float(s.group(1))
                except ValueError:
                    pass

            # Extract additional context
            description = line.strip()
            out.append({
                "id": m.group(),
                "cvss": score,
                "description": description
            })
    return out

def _extract_vuln_lines(text: str) -> list[str]:
    """Enhanced vulnerability line extraction"""
    vuln_lines = []


    for pattern in VULN_PATTERNS:
        matches = pattern.findall(text)
        vuln_lines.extend(matches)


    vuln_lines.extend([ln.strip() for ln in text.splitlines() if VULN_RE.search(ln)])

    return list(set(vuln_lines))  # Remove duplicates

def _score_to_severity(score: float | None) -> str:
    if score is None:
        return "Info"
    if score == 0.0:
        return "None"
    elif score < 4.0:
        return "Low"
    elif score < 7.0:
        return "Medium"
    elif score < 9.0:
        return "High"
    else:
        return "Critical"

def fetch_cvss_from_nvd(cve_id: str) -> float | None:
    """Fetch CVSS score from NVD with enhanced error handling"""
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    headers = {"User-Agent": "VulnerabilityScanner/1.0"}
    try:
        time.sleep(1.2)  # Rate limiting
        resp = requests.get(url, headers=headers, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        items = data.get("vulnerabilities", [])
        for item in items:
            metrics = item.get("cve", {}).get("metrics", {})
            for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if version in metrics and len(metrics[version]) > 0:
                    score = metrics[version][0]["cvssData"]["baseScore"]
                    print(f"[INFO] Found CVSS {score} for {cve_id}")
                    return float(score)
    except Exception as e:
        print(f"[ERROR] Failed to fetch CVSS for {cve_id}: {e}")
    return None


def run_scan(target: str, scan_mode: str = None) -> List[Dict[str, Any]]:
    """Enhanced Nmap vulnerability scanning"""
    mode = scan_mode or SCAN_MODE


    scripts, script_args = get_script_args(mode)


    base_args = {
        "fast": FAST_NMAP_ARGS,
        "balanced": BALANCED_NMAP_ARGS,
        "thorough": THOROUGH_NMAP_ARGS
    }

    nmap_args = base_args[mode]


    if mode != "thorough":
        port_range = TOP_PORTS_FAST if mode == "fast" else TOP_PORTS_THOROUGH
        nmap_args += f" -p {port_range}"


    nmap_args += f" --script {scripts}"


    if script_args:
        nmap_args += f' --script-args "{script_args}"'

    print(f"[+] Nmap vulnerability scan ({mode} mode) → {target}")
    print(f"    Arguments: {nmap_args}")
    print(f"    Scripts: {scripts}")

    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=target, arguments=nmap_args)
    except nmap.PortScannerError as err:
        raise RuntimeError(f"Nmap scan error: {err}")

    findings: list[dict] = []
    total_vulns = 0

    for host in nm.all_hosts():
        host_state = nm[host].state()
        print(f"[+] Processing host {host} (state: {host_state})")

        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            print(f"    Protocol {proto}: {len(ports)} ports")

            for port in ports:
                rec = nm[host][proto][port]

                service = rec.get("name", "unknown")
                product = f"{rec.get('product','')} {rec.get('version','')}".strip()
                state = rec.get("state", "unknown")

                # Get all script output
                script_results = rec.get("script", {})
                script_out = "\n".join(str(v) for v in script_results.values())

                # Enhanced vulnerability extraction
                cves = _extract_cves(script_out)
                miscfg = _extract_vuln_lines(script_out)

                # Fetch CVSS scores for CVEs without scores
                for cve in cves:
                    if cve["cvss"] is None:
                        cve["cvss"] = fetch_cvss_from_nvd(cve["id"])

                # Calculate severity
                highest = max((c["cvss"] for c in cves if c["cvss"]), default=None)

                # Enhanced severity calculation
                if cves:
                    severity = _score_to_severity(highest)
                elif miscfg:
                    severity = "Medium"  # Misconfigurations are at least medium
                elif state == "open" and service != "unknown":
                    severity = "Low"   # Open services are at least informational
                else:
                    severity = "Info"

                finding = {
                    "type": "nmap_scan",
                    "host": host,
                    "protocol": proto,
                    "port": port,
                    "state": state,
                    "service": service,
                    "product": product,
                    "cves": cves,
                    "misconfig": miscfg,
                    "cvss": highest,
                    "severity": severity,
                    "script_output": script_out if script_out.strip() else None
                }

                findings.append(finding)

                # Count vulnerabilities
                if cves or miscfg:
                    total_vulns += 1
                    print(f"    [VULN] {host}:{port} ({service}) - {len(cves)} CVEs, {len(miscfg)} misconfigs")

    print(f"[+] Scan complete: {len(findings)} findings, {total_vulns} vulnerabilities detected")
    return findings


def run_traffic_analysis(target: str, duration: int = 60, interface: str = None) -> List[Dict[str, Any]]:
    """Run network traffic analysis using Scapy"""
    if not SCAPY_AVAILABLE:
        print("[ERROR] Scapy not available for traffic analysis")
        return []

    print(f"[+] Starting traffic analysis for {duration} seconds...")

    analyzer = TrafficAnalyzer(target)


    def capture_packets():
        try:
            sniff(
                iface=interface,
                prn=analyzer.packet_handler,
                timeout=duration,
                store=False,
                stop_filter=lambda x: analyzer.stop_capture
            )
        except Exception as e:
            print(f"[ERROR] Packet capture failed: {e}")

    capture_thread = threading.Thread(target=capture_packets)
    capture_thread.daemon = True
    capture_thread.start()


    capture_thread.join(timeout=duration + 5)
    analyzer.stop_capture = True

    print(f"[+] Traffic analysis complete. {analyzer.packet_count} packets processed.")
    return analyzer.generate_findings()

def run_comprehensive_scan(target: str, traffic_duration: int = 60, scan_mode: str = "balanced") -> Dict[str, Any]:
    """Run both Nmap scan and traffic analysis"""
    print(f"[+] Starting comprehensive vulnerability assessment on {target}")
    print(f"[+] Scan mode: {scan_mode}, Traffic analysis: {traffic_duration}s")


    print("\n" + "="*50)
    print("PHASE 1: NMAP VULNERABILITY SCAN")
    print("="*50)
    nmap_findings = run_scan(target, scan_mode)


    traffic_findings = []
    if SCAPY_AVAILABLE:
        print("\n" + "="*50)
        print("PHASE 2: NETWORK TRAFFIC ANALYSIS")
        print("="*50)
        traffic_findings = run_traffic_analysis(target, traffic_duration)
    else:
        print("\n[INFO] Skipping traffic analysis (Scapy not available)")


    all_findings = nmap_findings + traffic_findings


    severity_counts = Counter([f.get('severity', 'Info') for f in all_findings])
    total_cves = sum(len(f.get('cves', [])) for f in nmap_findings)
    total_misconfigs = sum(len(f.get('misconfig', [])) for f in nmap_findings)

    summary = {
        'target': target,
        'scan_mode': scan_mode,
        'timestamp': datetime.now().isoformat(),
        'total_findings': len(all_findings),
        'nmap_findings': len(nmap_findings),
        'traffic_findings': len(traffic_findings),
        'severity_breakdown': dict(severity_counts),
        'total_cves': total_cves,
        'total_misconfigs': total_misconfigs,
        'findings': all_findings
    }

    return summary

def print_summary_report(results: Dict[str, Any]):
    """Print a formatted summary report"""
    print("\n" + "="*70)
    print("VULNERABILITY ASSESSMENT SUMMARY")
    print("="*70)
    print(f"Target: {results['target']}")
    print(f"Scan Mode: {results['scan_mode']}")
    print(f"Scan Time: {results['timestamp']}")
    print(f"Total Findings: {results['total_findings']}")
    print(f"CVEs Identified: {results['total_cves']}")
    print(f"Misconfigurations: {results['total_misconfigs']}")

    print("\nSEVERITY BREAKDOWN:")
    for severity, count in results['severity_breakdown'].items():
        print(f"  {severity}: {count}")

    print(f"\nFINDINGS BREAKDOWN:")
    print(f"  Nmap Scan Results: {results['nmap_findings']}")
    print(f"  Traffic Analysis: {results['traffic_findings']}")


    critical_high = [f for f in results['findings']
                    if f.get('severity') in ['Critical', 'High']]

    if critical_high:
        print(f"\nCRITICAL/HIGH SEVERITY ISSUES ({len(critical_high)}):")
        for i, finding in enumerate(critical_high[:10], 1):  # Show top 10
            host = finding.get('host', 'N/A')
            port = finding.get('port', 'N/A')
            service = finding.get('service', finding.get('category', 'Unknown'))
            cves = finding.get('cves', [])
            misconfigs = finding.get('misconfig', [])

            print(f"  {i}. {host}:{port} ({service}) - {finding.get('severity')}")
            if cves:
                cve_list = ', '.join([f"{c['id']} (CVSS:{c.get('cvss', 'N/A')})" for c in cves[:3]])
                print(f"     CVEs: {cve_list}")
            if misconfigs:
                print(f"     Issues: {len(misconfigs)} configuration problems")

    print("="*70)


if __name__ == "__main__":
    import sys
    import json

    if len(sys.argv) < 2:
        print("Usage: python scanner.py <target> [traffic_duration] [scan_mode]")
        print("Scan modes: fast, balanced, thorough")
        print("Examples:")
        print("  python scanner.py 192.168.1.100 30 fast      # Quick scan")
        print("  python scanner.py 192.168.1.0/24 60 balanced # Medium scan")
        print("  python scanner.py 192.168.1.100 90 thorough  # Full scan")
        print("\nEnvironment variables:")
        print("  VULNERS_API_KEY - API key for enhanced vulnerability detection")
        sys.exit(1)

    target = sys.argv[1]
    duration = int(sys.argv[2]) if len(sys.argv) > 2 else 60
    scan_mode = sys.argv[3] if len(sys.argv) > 3 else "balanced"

    print(f"[+] Enhanced Vulnerability Scanner starting...")
    print(f"[+] Target: {target}")
    print(f"[+] Mode: {scan_mode}")
    print(f"[+] Vulners API: {'Enabled' if USE_VULNERS else 'Disabled'}")


    try:
        results = run_comprehensive_scan(target, duration, scan_mode)


        print_summary_report(results)


        output_file = f"vuln_assessment_{target.replace('/', '_').replace(':', '_')}.json"
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)

        print(f"\n[+] Detailed results saved to: {output_file}")

    except Exception as e:
        print(f"[ERROR] Scan failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)