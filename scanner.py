from __future__ import annotations
import requests
import time
import os, re
import psutil
import platform
import threading
from collections import defaultdict, Counter
from typing import List, Dict, Any
from datetime import datetime
import socket
from typing import Literal
import csv



SCAN_MODE = "balanced"  # Default scan mode
FAST_NMAP_ARGS = "-T4 -sV -sC"  # Added vuln scanning
BALANCED_NMAP_ARGS = "-T4 -A -sV -sC -O --script vuln"  # Enhanced vuln scanning
THOROUGH_NMAP_ARGS = "-T4 -A -sS -sV -sC -O -Pn -p- --script vuln,default,exploit"  # Comprehensive
TOP_PORTS_FAST = "1-65535"
TOP_PORTS_THOROUGH = "1-65535"  # More reasonable than full range


API_KEY = os.getenv("VULNERS_API_KEY", "").strip()
USE_VULNERS = bool(API_KEY)


def get_script_args(mode: str = "balanced"):
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
        self.interface = self._get_best_interface()

    def _get_best_interface(self):
        try:
            # Get default interface based on OS
            if platform.system() == "Windows":
                # On Windows, try to find active Ethernet or WiFi adapter
                interfaces = psutil.net_if_addrs()
                for iface_name, addrs in interfaces.items():
                    if any(addr.family == socket.AF_INET and not addr.address.startswith('127.')
                           for addr in addrs):
                        # Prefer Ethernet over WiFi
                        if 'ethernet' in iface_name.lower() or 'local area connection' in iface_name.lower():
                            return iface_name
                        elif 'wi-fi' in iface_name.lower() or 'wireless' in iface_name.lower():
                            return iface_name
                # Fallback to first non-loopback interface
                for iface_name, addrs in interfaces.items():
                    if any(addr.family == socket.AF_INET and not addr.address.startswith('127.')
                           for addr in addrs):
                        return iface_name
            else:
                # Linux/Unix - use route command or check common interfaces
                import subprocess
                try:
                    result = subprocess.run(['ip', 'route', 'get', '8.8.8.8'],
                                            capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        # Extract interface from output
                        for line in result.stdout.split('\n'):
                            if 'dev' in line:
                                parts = line.split()
                                dev_idx = parts.index('dev')
                                if dev_idx + 1 < len(parts):
                                    return parts[dev_idx + 1]
                except:
                    pass

                # Fallback to common interface names
                common_interfaces = ['eth0', 'ens33', 'ens18', 'enp0s3', 'wlan0', 'wlp2s0']
                interfaces = psutil.net_if_addrs().keys()
                for iface in common_interfaces:
                    if iface in interfaces:
                        return iface

                # Last resort - first non-loopback interface
                for iface_name, addrs in psutil.net_if_addrs().items():
                    if any(addr.family == socket.AF_INET and not addr.address.startswith('127.')
                           for addr in addrs):
                        return iface_name
        except Exception as e:
            print(f"[WARNING] Could not auto-detect interface: {e}")

        return None

    def packet_handler(self, pkt):
        try:
            self.packet_count += 1

            # Check if packet has IP layer before processing
            if not pkt.haslayer(IP):
                return  # Skip non-IP packets

            self.captured_packets.append(pkt)

            # Check for suspicious ports
            if pkt.haslayer(TCP) and pkt[TCP].dport in [4444, 1337, 31337]:
                self.findings.append({
                    "type": "network_traffic",
                    "category": "Suspicious Port",
                    "host": pkt[IP].dst,
                    "port": pkt[TCP].dport,
                    "service": "Unknown",
                    "severity": "Medium",
                    "description": f"Suspicious traffic to port {pkt[TCP].dport}"
                })

            self._analyze_tcp_traffic(pkt)
            self._analyze_udp_traffic(pkt)
            self._analyze_dns_traffic(pkt)
            self._analyze_suspicious_patterns(pkt)

        except Exception as e:
            # Silently handle packet processing errors to avoid spam
            pass

    def _analyze_tcp_traffic(self, packet):
        if not packet.haslayer(TCP) or not packet.haslayer(IP):
            return

        try:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

            # Track connection patterns
            connection = f"{packet[IP].src}:{src_port} -> {packet[IP].dst}:{dst_port}"
            self.connection_stats[connection] += 1

            # Check for plaintext protocols
            if dst_port in PLAINTEXT_PROTOCOLS:
                self.unencrypted_services.add((packet[IP].dst, dst_port, PLAINTEXT_PROTOCOLS[dst_port]))

            # Look for credentials in plaintext
            if packet.haslayer(Raw):
                payload = packet[Raw].load
                self._check_for_credentials(payload, packet[IP].src, packet[IP].dst, dst_port)

            # Detect suspicious port activity
            if dst_port in SUSPICIOUS_PORTS:
                self.suspicious_traffic.append({
                    'type': 'suspicious_port',
                    'src': packet[IP].src,
                    'dst': packet[IP].dst,
                    'port': dst_port,
                    'protocol': 'TCP',
                    'timestamp': datetime.now()
                })
        except Exception:
            pass

    def _analyze_udp_traffic(self, packet):
        if not packet.haslayer(UDP) or not packet.haslayer(IP):
            return

        try:
            dst_port = packet[UDP].dport

            # SNMP traffic (often misconfigured)
            if dst_port == 161:
                self.suspicious_traffic.append({
                    'type': 'snmp_traffic',
                    'src': packet[IP].src,
                    'dst': packet[IP].dst,
                    'port': dst_port,
                    'protocol': 'UDP',
                    'timestamp': datetime.now()
                })
        except Exception:
            pass

    def _analyze_dns_traffic(self, packet):
        try:
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
        except Exception:
            pass

    def _check_for_credentials(self, payload: bytes, src_ip: str, dst_ip: str, port: int):
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
        try:
            # Port scanning detection (simplified)
            if packet.haslayer(TCP):
                # SYN scan detection
                if packet[TCP].flags == 2:  # SYN flag
                    self.connection_stats[f"syn_scan_{packet[IP].src}"] += 1

            # ARP spoofing detection
            if packet.haslayer(ARP):
                if packet[ARP].op == 2:  # ARP reply
                    self.suspicious_traffic.append({
                        'type': 'arp_reply',
                        'src_mac': packet[ARP].hwsrc,
                        'src_ip': packet[ARP].psrc,
                        'dst_ip': packet[ARP].pdst,
                        'timestamp': datetime.now()
                    })
        except Exception:
            pass

    def generate_findings(self) -> List[Dict[str, Any]]:
        findings = []
        reported = set()

        # Unencrypted services
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

        # Credential exposure
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

        # Suspicious traffic patterns
        suspicious_counts = Counter([s['type'] for s in self.suspicious_traffic])
        for traffic_type, count in suspicious_counts.items():
            if count > 5:
                findings.append({
                    'type': 'network_traffic',
                    'category': 'suspicious_activity',
                    'description': f'High volume of {traffic_type} detected ({count} instances)',
                    'severity': 'Medium',
                    'cvss': 4.0
                })

        # Generate findings from captured packets
        processed_connections = set()
        for pkt in self.captured_packets[:100]:  # Limit to prevent spam
            try:
                if not pkt.haslayer(IP):
                    continue

                ip_layer = pkt.getlayer(IP)
                host = ip_layer.dst

                if pkt.haslayer(TCP):
                    proto = "TCP"
                    dport = pkt[TCP].dport
                elif pkt.haslayer(UDP):
                    proto = "UDP"
                    dport = pkt[UDP].dport
                else:
                    continue

                connection_key = (host, dport, proto)
                if connection_key in processed_connections or (host, dport) in reported:
                    continue

                processed_connections.add(connection_key)

                try:
                    service = socket.getservbyport(dport)
                except:
                    service = "unknown"

                findings.append({
                    "type": "network_traffic",
                    "category": proto.lower(),
                    "host": host,
                    "port": dport,
                    "service": service,
                    "severity": "Info",
                    "description": f"Observed {proto} traffic to port {dport} on {host}"
                })
            except Exception:
                continue

        # Traffic summary
        if self.packet_count > 0:
            findings.append({
                'type': 'network_traffic',
                'category': 'summary',
                'host': 'N/A',
                'port': 'N/A',
                'severity': 'Info',
                'description': f"Captured and analyzed {self.packet_count} packets on interface {self.interface}"
            })

        return findings


def run_traffic_analysis(target: str, duration: int = 60, interface: str = None) -> List[Dict[str, Any]]:
    if not SCAPY_AVAILABLE:
        print("[ERROR] Scapy not available for traffic analysis")
        return []

    print(f"[+] Starting traffic analysis for {duration} seconds...")

    analyzer = TrafficAnalyzer(target)

    # Use provided interface or auto-detected one
    selected_interface = interface or analyzer.interface
    if selected_interface:
        print(f"[+] Using network interface: {selected_interface}")
    else:
        print("[WARNING] Could not detect network interface, using default")
        selected_interface = None

    # Enhanced packet capture with better error handling
    def capture_packets():
        try:
            print(f"[+] Starting packet capture...")

            # Try multiple approaches for packet capture
            capture_methods = [
                # Method 1: Basic sniff with interface
                lambda: sniff(
                    iface=selected_interface,
                    prn=analyzer.packet_handler,
                    timeout=duration,
                    store=False,
                    stop_filter=lambda x: analyzer.stop_capture,
                    filter="ip"  # Only capture IP packets
                ),
                # Method 2: Sniff without interface specification
                lambda: sniff(
                    prn=analyzer.packet_handler,
                    timeout=duration,
                    store=False,
                    stop_filter=lambda x: analyzer.stop_capture,
                    filter="ip"
                ),
                # Method 3: Basic sniff with minimal filters
                lambda: sniff(
                    prn=analyzer.packet_handler,
                    timeout=duration,
                    store=False,
                    stop_filter=lambda x: analyzer.stop_capture
                )
            ]

            last_error = None
            for i, method in enumerate(capture_methods, 1):
                try:
                    print(f"[+] Trying capture method {i}...")
                    method()
                    break  # Success, exit loop
                except Exception as e:
                    last_error = e
                    print(f"[WARNING] Capture method {i} failed: {e}")
                    if i < len(capture_methods):
                        print(f"[+] Trying alternative method...")
                        time.sleep(1)
                    else:
                        print(f"[ERROR] All capture methods failed. Last error: {e}")

        except Exception as e:
            print(f"[ERROR] Packet capture failed: {e}")
            print("[INFO] Continuing with limited analysis...")

    # Start capture thread
    capture_thread = threading.Thread(target=capture_packets, daemon=True)
    capture_thread.start()

    # Progress indicator
    start_time = time.time()
    while capture_thread.is_alive() and time.time() - start_time < duration + 5:
        elapsed = int(time.time() - start_time)
        if elapsed > 0 and elapsed % 15 == 0:  # Print every 15 seconds
            print(f"[+] Traffic analysis progress: {elapsed}s elapsed, {analyzer.packet_count} packets captured")
        time.sleep(1)

    # Stop capture
    analyzer.stop_capture = True
    capture_thread.join(timeout=5)

    print(f"[+] Traffic analysis complete. {analyzer.packet_count} packets processed.")

    # Generate findings even if capture had issues
    findings = analyzer.generate_findings()

    if analyzer.packet_count == 0:
        print("[WARNING] No packets were captured. This might indicate:")
        print("  - Insufficient privileges (try running as administrator/root)")
        print("  - Network interface issues")
        print("  - Firewall blocking packet capture")
        print("  - No network traffic during capture period")

        # Add a warning finding
        findings.append({
            'type': 'network_traffic',
            'category': 'warning',
            'host': 'N/A',
            'port': 'N/A',
            'severity': 'Info',
            'description': 'No network packets were captured. Consider running with elevated privileges or checking network configuration.'
        })

    return findings

def _extract_cves(text: str) -> list[dict]:
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
    vuln_lines = []

    # Use multiple patterns
    for pattern in VULN_PATTERNS:
        matches = pattern.findall(text)
        vuln_lines.extend(matches)

    # Also use original pattern
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
    mode = scan_mode or SCAN_MODE

    # Get script configuration for this mode
    scripts, script_args = get_script_args(mode)

    # Build nmap arguments
    base_args = {
        "fast": FAST_NMAP_ARGS,
        "balanced": BALANCED_NMAP_ARGS,
        "thorough": THOROUGH_NMAP_ARGS
    }

    nmap_args = base_args[mode]

    # Add port range for fast/balanced modes
    if mode != "thorough":
        port_range = TOP_PORTS_FAST if mode == "fast" else TOP_PORTS_THOROUGH
        nmap_args += f" -p {port_range}"

    # Add scripts
    nmap_args += f" --script {scripts}"

    # Add script arguments if available
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
    if not SCAPY_AVAILABLE:
        print("[ERROR] Scapy not available for traffic analysis")
        return []

    print(f"[+] Starting traffic analysis for {duration} seconds...")

    analyzer = TrafficAnalyzer(target)

    # Start packet capture in background thread
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

    # Wait for capture to complete
    capture_thread.join(timeout=duration + 5)
    analyzer.stop_capture = True

    print(f"[+] Traffic analysis complete. {analyzer.packet_count} packets processed.")
    return analyzer.generate_findings()

def run_comprehensive_scan(target: str, traffic_duration: int = 60, scan_mode: str = "balanced") -> Dict[str, Any]:
    print(f"[+] Starting comprehensive vulnerability assessment on {target}")
    print(f"[+] Scan mode: {scan_mode}, Traffic analysis: {traffic_duration}s")

    # Run Nmap scan
    print("\n" + "="*50)
    print("PHASE 1: NMAP VULNERABILITY SCAN")
    print("="*50)
    nmap_findings = run_scan(target, scan_mode)

    # Run traffic analysis if Scapy is available
    traffic_findings = []
    if SCAPY_AVAILABLE:
        print("\n" + "="*50)
        print("PHASE 2: NETWORK TRAFFIC ANALYSIS")
        print("="*50)
        traffic_findings = run_traffic_analysis(target, traffic_duration)
    else:
        print("\n[INFO] Skipping traffic analysis (Scapy not available)")

    # Combine and summarize results
    all_findings = nmap_findings + traffic_findings

    # Generate summary statistics
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

def save_findings_to_file(findings: List[Dict[str, Any]], filename: str, file_format: Literal["json", "csv", "txt"] = "json") -> None:
    try:
        if file_format == "json":
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(findings, f, indent=4)
            print(f"[+] Findings saved to {filename} (JSON)")

        elif file_format == "csv":
            if not findings:
                print("[WARNING] No findings to save.")
                return

            # Optional: define preferred column order
            preferred_order = ['type', 'category', 'host', 'port', 'service', 'severity', 'description', 'cvss']
            keys = sorted({k for d in findings for k in d})
            ordered_keys = [k for k in preferred_order if k in keys] + [k for k in keys if k not in preferred_order]

            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=ordered_keys)
                writer.writeheader()
                writer.writerows(findings)
            print(f"[+] Findings saved to {filename} (CSV)")

        elif file_format == "txt":
            with open(filename, 'w', encoding='utf-8') as f:
                for entry in findings:
                    f.write("─" * 50 + "\n")
                    for key, value in entry.items():
                        f.write(f"{key.capitalize():>12}: {value}\n")
                    f.write("\n")
            print(f"[+] Findings saved to {filename} (TXT)")

        else:
            print(f"[ERROR] Unsupported file format: {file_format}")

    except Exception as e:
        print(f"[ERROR] Could not save findings to file: {e}")

def print_summary_report(results: Dict[str, Any]):
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

    # Show top vulnerabilities
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

    # Run comprehensive scan
    try:
        results = run_comprehensive_scan(target, duration, scan_mode)

        # Print summary
        print_summary_report(results)

        # Save detailed results
        output_file = f"vuln_assessment_{target.replace('/', '_').replace(':', '_')}.json"
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)

        print(f"\n[+] Detailed results saved to: {output_file}")

    except Exception as e:
        print(f"[ERROR] Scan failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)