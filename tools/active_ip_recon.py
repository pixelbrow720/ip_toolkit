#!/usr/bin/env python3
"""
Alat Investigasi Aktif IP

Tool ini melakukan pengumpulan informasi secara aktif terhadap alamat IP target.
CATATAN: Gunakan hanya pada sistem yang Anda memiliki izin untuk melakukan scanning.

Fitur:
- Port scanning (TCP/UDP)
- Service/version detection
- Banner grabbing
- Vulnerability checking
- HTTP server fingerprinting
- SSL/TLS certificate analysis
- Response time measurement

Penggunaan: python active_ip_recon.py [-h] [--ports PORTS] [--intensity {1,2,3,4,5}] [--output OUTPUT] ips [ips ...]
"""

import sys
import os
import json
import time
import socket
import ipaddress
import argparse
import logging
import concurrent.futures
import subprocess
import ssl
import requests
import warnings
from datetime import datetime
from urllib.parse import urlparse

# Konfigurasi logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("ActiveIPRecon")

# Direktori untuk menyimpan hasil
OUTPUT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reports", "active_recon")

# Buat direktori jika belum ada
if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)

# Disable warnings untuk SSL certificate verification
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

class ActiveIPInvestigator:
    """
    Kelas untuk melakukan investigasi aktif terhadap alamat IP
    """
    
    def __init__(self, intensity=3, ports=None, output_dir=OUTPUT_DIR, timeout=5):
        """
        Inisialisasi investigator
        
        Args:
            intensity (int): Level intensitas scanning (1-5)
            ports (str): Port yang akan di-scan, format Nmap (mis. "22,80,443" atau "1-1000")
            output_dir (str): Direktori untuk menyimpan hasil
            timeout (int): Timeout untuk koneksi (detik)
        """
        self.intensity = min(max(intensity, 1), 5)  # Pastikan range 1-5
        self.ports = ports
        self.output_dir = output_dir
        self.timeout = timeout
        self.results = {}
        
        # Level intensitas port scanning
        self.port_configs = {
            1: {"top_ports": "20", "speed": "T3"},    # Quick scan
            2: {"top_ports": "100", "speed": "T3"},   # Common ports
            3: {"top_ports": "1000", "speed": "T4"},  # Standard scan
            4: {"port_range": "1-10000", "speed": "T4"}, # Extended scan
            5: {"port_range": "1-65535", "speed": "T5"} # Full scan
        }
        
        # Periksa konfigurasi Nmap
        self.has_nmap = self._check_command("nmap")
        if not self.has_nmap:
            logger.warning("Nmap tidak ditemukan! Port scanning akan dibatasi atau menggunakan metode native.")
            
        # Check vulners script (diperlukan untuk vulnerability check dengan NSE)
        self.has_vulners = self._check_nmap_script("vulners") if self.has_nmap else False
        
        if not self.has_vulners:
            logger.warning("Nmap NSE script 'vulners' tidak ditemukan. Vulnerability checking akan dibatasi.")
    
    def _check_command(self, command):
        """
        Memeriksa apakah suatu command tersedia di sistem
        
        Args:
            command (str): Nama command yang akan diperiksa
            
        Returns:
            bool: True jika command tersedia, False jika tidak
        """
        try:
            subprocess.run([command, "--version"], 
                           stdout=subprocess.PIPE, 
                           stderr=subprocess.PIPE, 
                           check=False)
            return True
        except FileNotFoundError:
            return False
    
    def _check_nmap_script(self, script_name):
        """
        Memeriksa apakah NSE script tertentu tersedia
        
        Args:
            script_name (str): Nama NSE script yang akan diperiksa
            
        Returns:
            bool: True jika script tersedia, False jika tidak
        """
        try:
            result = subprocess.run(["nmap", "--script-help", script_name], 
                                    stdout=subprocess.PIPE, 
                                    stderr=subprocess.PIPE, 
                                    check=False)
            return "ERROR" not in result.stderr.decode()
        except Exception:
            return False
    
    def validate_ip(self, ip_addr):
        """
        Memvalidasi alamat IP
        
        Args:
            ip_addr (str): Alamat IP yang akan divalidasi
            
        Returns:
            bool: True jika IP valid, False jika tidak
        """
        try:
            ipaddress.ip_address(ip_addr)
            return True
        except ValueError:
            return False
    
    def port_scan_native(self, ip_addr, port_list):
        """
        Melakukan port scanning menggunakan socket Python native
        
        Args:
            ip_addr (str): Alamat IP target
            port_list (list): Daftar port yang akan di-scan
            
        Returns:
            dict: Hasil port scanning {port: {"status": "open/closed", "service": "unknown"}}
        """
        results = {}
        socket.setdefaulttimeout(self.timeout)
        
        for port in port_list:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                result = s.connect_ex((ip_addr, port))
                s.close()
                
                if result == 0:
                    # Port terbuka
                    results[port] = {
                        "status": "open",
                        "service": self.guess_service(port)
                    }
                    
                    # Grab banner jika port terbuka
                    banner = self.grab_banner(ip_addr, port)
                    if banner:
                        results[port]["banner"] = banner
            except Exception:
                results[port] = {"status": "error", "service": "unknown"}
                
        return results
    
    def guess_service(self, port):
        """
        Menebak service berdasarkan port number
        
        Args:
            port (int): Nomor port
            
        Returns:
            str: Nama service
        """
        common_ports = {
            21: "ftp",
            22: "ssh",
            23: "telnet",
            25: "smtp",
            53: "dns",
            80: "http",
            110: "pop3",
            115: "sftp",
            135: "msrpc",
            139: "netbios",
            143: "imap",
            194: "irc",
            443: "https",
            445: "smb",
            1433: "mssql",
            1521: "oracle",
            3306: "mysql",
            3389: "rdp",
            5432: "postgresql",
            5900: "vnc",
            8080: "http-proxy",
            8443: "https-alt",
            27017: "mongodb"
        }
        
        return common_ports.get(port, "unknown")
    
    def grab_banner(self, ip_addr, port):
        """
        Mengambil banner dari port yang terbuka
        
        Args:
            ip_addr (str): Alamat IP target
            port (int): Nomor port
            
        Returns:
            str: Banner, atau None jika gagal
        """
        common_prompts = {
            21: b"", # FTP biasanya langsung mengirimkan banner
            22: b"", # SSH langsung mengirimkan banner
            23: b"", # Telnet langsung mengirimkan banner
            25: b"EHLO example.com\r\n", # SMTP
            110: b"USER test\r\n", # POP3
            143: b"A1 CAPABILITY\r\n", # IMAP
            80: b"GET / HTTP/1.0\r\n\r\n", # HTTP
            443: b"GET / HTTP/1.0\r\n\r\n", # HTTPS (setelah TLS handshake)
        }
        
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((ip_addr, port))
            
            # Jika HTTPS port, gunakan SSL wrapper
            if port == 443:
                try:
                    s = ssl.wrap_socket(s, ssl_version=ssl.PROTOCOL_TLS)
                except Exception:
                    # Gagal dalam TLS handshake, coba raw grab
                    pass
            
            # Kirim prompt jika ada
            if port in common_prompts:
                s.send(common_prompts[port])
            
            # Baca response
            banner = s.recv(1024)
            s.close()
            
            # Decode UTF-8 dengan fallback ke latin-1
            try:
                return banner.decode('utf-8').strip()
            except UnicodeDecodeError:
                return banner.decode('latin-1').strip()
        except Exception:
            return None
    
    def scan_with_nmap(self, ip_addr):
        """
        Melakukan scanning menggunakan Nmap
        
        Args:
            ip_addr (str): Alamat IP target
            
        Returns:
            dict: Hasil scanning Nmap
        """
        if not self.has_nmap:
            return {"error": "Nmap tidak tersedia"}
            
        # Tentukan port berdasarkan konfigurasi
        if self.ports:
            port_arg = f"-p {self.ports}"
        else:
            config = self.port_configs[self.intensity]
            if "top_ports" in config:
                port_arg = f"--top-ports {config['top_ports']}"
            else:
                port_arg = f"-p {config['port_range']}"
                
        # Tentukan kecepatan scanning
        speed = self.port_configs[self.intensity]["speed"]
        
        # Basic arguments untuk Nmap
        args = [
            "nmap",
            "-sV",              # Version detection
            "-O",               # OS detection
            "-A",               # Enable OS detection, version detection, script scanning, and traceroute
            f"-{speed}",        # Speed
            port_arg,
            "--open",           # Show only open ports
            "-oX", "-",         # Output XML ke stdout
            ip_addr
        ]
        
        # Tambahkan script vulnerability check jika ada
        if self.has_vulners and self.intensity >= 4:
            args.insert(5, "--script=vulners")
            
        try:
            logger.info(f"Menjalankan Nmap: {' '.join(args)}")
            process = subprocess.run(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False
            )
            
            if process.returncode != 0:
                error = process.stderr.decode()
                logger.error(f"Nmap error: {error}")
                return {"error": error}
                
            # Parse XML output
            xml_output = process.stdout.decode()
            
            # Simpan juga sebagai raw output
            return {
                "raw": xml_output,
                "command": " ".join(args)
            }
        except Exception as e:
            logger.error(f"Error menjalankan Nmap: {str(e)}")
            return {"error": str(e)}
    
    def analyze_http_server(self, ip_addr, port=80, use_ssl=False):
        """
        Menganalisis HTTP server
        
        Args:
            ip_addr (str): Alamat IP target
            port (int): Port HTTP
            use_ssl (bool): Gunakan HTTPS
            
        Returns:
            dict: Informasi HTTP server
        """
        protocol = "https" if use_ssl else "http"
        url = f"{protocol}://{ip_addr}:{port}"
        
        try:
            # Kirim GET request
            response = requests.get(
                url,
                timeout=self.timeout,
                verify=False,
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
                }
            )
            
            # Ekstrak header
            headers = dict(response.headers)
            
            # Finger printing berdasarkan header
            server_type = headers.get("Server", "Unknown")
            powered_by = headers.get("X-Powered-By", "Unknown")
            
            # Simpan hasil
            result = {
                "url": url,
                "status_code": response.status_code,
                "server": server_type,
                "powered_by": powered_by,
                "headers": headers,
                "response_time": response.elapsed.total_seconds(),
                "content_length": len(response.content),
            }
            
            # Cek title halaman jika HTML
            content_type = headers.get("Content-Type", "")
            if "text/html" in content_type:
                try:
                    from bs4 import BeautifulSoup
                    soup = BeautifulSoup(response.text, 'html.parser')
                    if soup.title:
                        result["title"] = soup.title.string.strip()
                except ImportError:
                    # BeautifulSoup tidak tersedia
                    pass
            
            return result
        except requests.RequestException as e:
            return {"error": str(e), "url": url}
    
    def analyze_ssl_certificate(self, ip_addr, port=443):
        """
        Menganalisis SSL certificate
        
        Args:
            ip_addr (str): Alamat IP target
            port (int): Port SSL/TLS
            
        Returns:
            dict: Informasi SSL certificate
        """
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((ip_addr, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=ip_addr) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    cipher = ssock.cipher()
                    
                    # Dapatkan Subject dan Issuer
                    if not cert:
                        return {"error": "No certificate information available"}
                    
                    result = {
                        "issuer": cert.get("issuer", []),
                        "subject": cert.get("subject", []),
                        "version": cert.get("version", ""),
                        "serialNumber": cert.get("serialNumber", ""),
                        "notBefore": cert.get("notBefore", ""),
                        "notAfter": cert.get("notAfter", ""),
                        "subjectAltName": cert.get("subjectAltName", []),
                        "OCSP": cert.get("OCSP", []),
                        "caIssuers": cert.get("caIssuers", []),
                        "crlDistributionPoints": cert.get("crlDistributionPoints", []),
                        "cipher": {
                            "name": cipher[0],
                            "version": cipher[1],
                            "bits": cipher[2]
                        }
                    }
                    
                    return result
        except Exception as e:
            return {"error": str(e)}
    
    def investigate_ip(self, ip_addr):
        """
        Melakukan investigasi aktif terhadap alamat IP
        
        Args:
            ip_addr (str): Alamat IP target
            
        Returns:
            dict: Hasil investigasi
        """
        if not self.validate_ip(ip_addr):
            return {
                "status": "error",
                "error": f"Invalid IP address: {ip_addr}"
            }
            
        logger.info(f"Menginvestigasi IP: {ip_addr}")
        
        # Jalankan scanning dengan Nmap
        result = {
            "ip": ip_addr,
            "timestamp": datetime.now().isoformat(),
            "scan_intensity": self.intensity,
        }
        
        # Lakukan nmap scan jika tersedia
        if self.has_nmap:
            result["nmap_scan"] = self.scan_with_nmap(ip_addr)
            
            # Native port scan hanya jika nmap gagal
            if "error" in result["nmap_scan"]:
                if self.ports:
                    ports = []
                    for p in self.ports.split(","):
                        if "-" in p:
                            start, end = map(int, p.split("-"))
                            ports.extend(range(start, end + 1))
                        else:
                            ports.append(int(p))
                else:
                    # Default scan top ports saja
                    ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080]
                    
                result["port_scan"] = self.port_scan_native(ip_addr, ports)
        else:
            # Jika tidak ada nmap, gunakan native port scanner
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080]
            result["port_scan"] = self.port_scan_native(ip_addr, ports)
        
        # Lakukan HTTP scanning jika port 80 terdeteksi terbuka
        try:
            result["http_analysis"] = self.analyze_http_server(ip_addr, 80)
        except Exception as e:
            result["http_analysis"] = {"error": str(e)}
        
        # Lakukan HTTPS scanning jika port 443 terdeteksi terbuka
        try:
            result["https_analysis"] = self.analyze_http_server(ip_addr, 443, use_ssl=True)
            result["ssl_certificate"] = self.analyze_ssl_certificate(ip_addr, 443)
        except Exception as e:
            result["https_analysis"] = {"error": str(e)}
        
        # Tambahkan ke hasil
        self.results[ip_addr] = result
        
        logger.info(f"Investigasi aktif selesai untuk IP: {ip_addr}")
        return result
    
    def investigate_multiple_ips(self, ip_list, parallel=False):
        """
        Menjalankan investigasi terhadap beberapa IP
        
        Args:
            ip_list (list): Daftar alamat IP yang akan diinvestigasi
            parallel (bool): Jalankan penyelidikan secara paralel
            
        Returns:
            dict: Hasil investigasi untuk semua IP
        """
        self.results = {}
        
        # Hanya jalankan paralel jika diminta dan ada lebih dari 1 IP
        if parallel and len(ip_list) > 1:
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(5, len(ip_list))) as executor:
                executor.map(self.investigate_ip, ip_list)
        else:
            for ip in ip_list:
                self.investigate_ip(ip)
                
        return self.results
    
    def save_results(self, filename=None):
        """
        Menyimpan hasil investigasi ke file
        
        Args:
            filename (str): Nama file untuk menyimpan hasil
            
        Returns:
            str: Path file hasil
        """
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"active_investigation_{timestamp}.json"
            
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, 'w') as f:
            json.dump(self.results, f, indent=2)
            
        logger.info(f"Hasil disimpan ke: {filepath}")
        return filepath
    
    def generate_report(self):
        """
        Membuat laporan dari hasil investigasi
        
        Returns:
            str: Laporan dalam format text
        """
        report = []
        report.append("=" * 70)
        report.append("LAPORAN INVESTIGASI AKTIF IP")
        report.append("=" * 70)
        report.append(f"Waktu Laporan: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Jumlah IP Diinvestigasi: {len(self.results)}")
        report.append(f"Level Intensitas Scan: {self.intensity}/5")
        report.append("")
        
        for ip, data in self.results.items():
            report.append("=" * 70)
            report.append(f"TARGET: {ip}")
            report.append("=" * 70)
            
            # Port scan results
            report.append("\n== PORT SCAN RESULTS ==")
            
            if "port_scan" in data:
                # Format dari port_scan native
                open_ports = []
                for port, info in data["port_scan"].items():
                    if info.get("status") == "open":
                        service = info.get("service", "unknown")
                        banner = info.get("banner", "")
                        banner_info = f" - {banner}" if banner else ""
                        open_ports.append(f"- Port {port} ({service}){banner_info}")
                
                if open_ports:
                    report.append("Open Ports:")
                    report.extend(open_ports)
                else:
                    report.append("No open ports found.")
            elif "nmap_scan" in data and "error" not in data["nmap_scan"]:
                report.append("Scan dilakukan menggunakan Nmap.")
                report.append("Lihat file JSON untuk hasil lengkap Nmap.")
            else:
                report.append("Port scan data tidak tersedia.")
            
            # HTTP Server
            if "http_analysis" in data and "error" not in data.get("http_analysis", {}):
                http = data["http_analysis"]
                report.append("\n== HTTP SERVER (PORT 80) ==")
                report.append(f"Status Code: {http.get('status_code')}")
                report.append(f"Server: {http.get('server')}")
                report.append(f"Powered By: {http.get('powered_by')}")
                if "title" in http:
                    report.append(f"Page Title: {http.get('title')}")
                report.append(f"Response Time: {http.get('response_time')} seconds")
            
            # HTTPS Server
            if "https_analysis" in data and "error" not in data.get("https_analysis", {}):
                https = data["https_analysis"]
                report.append("\n== HTTPS SERVER (PORT 443) ==")
                report.append(f"Status Code: {https.get('status_code')}")
                report.append(f"Server: {https.get('server')}")
                report.append(f"Powered By: {https.get('powered_by')}")
                if "title" in https:
                    report.append(f"Page Title: {https.get('title')}")
                report.append(f"Response Time: {https.get('response_time')} seconds")
            
            # SSL Certificate
            if "ssl_certificate" in data and "error" not in data.get("ssl_certificate", {}):
                ssl_cert = data["ssl_certificate"]
                report.append("\n== SSL CERTIFICATE ==")
                
                # Subject
                if "subject" in ssl_cert and ssl_cert["subject"]:
                    subject_parts = []
                    for part in ssl_cert["subject"]:
                        for key, value in part:
                            subject_parts.append(f"{key}={value}")
                    report.append(f"Subject: {', '.join(subject_parts)}")
                
                # Issuer
                if "issuer" in ssl_cert and ssl_cert["issuer"]:
                    issuer_parts = []
                    for part in ssl_cert["issuer"]:
                        for key, value in part:
                            issuer_parts.append(f"{key}={value}")
                    report.append(f"Issuer: {', '.join(issuer_parts)}")
                
                # Validity
                if "notBefore" in ssl_cert and "notAfter" in ssl_cert:
                    report.append(f"Valid From: {ssl_cert['notBefore']}")
                    report.append(f"Valid To: {ssl_cert['notAfter']}")
                
                # Cipher
                if "cipher" in ssl_cert:
                    cipher = ssl_cert["cipher"]
                    report.append(f"Cipher: {cipher.get('name')} {cipher.get('version')} ({cipher.get('bits')} bits)")
            
            report.append("\n" + "-" * 70 + "\n")
            
        return "\n".join(report)
    
    def save_report(self, report_text, filename=None):
        """
        Menyimpan laporan ke file
        
        Args:
            report_text (str): Isi laporan
            filename (str): Nama file untuk menyimpan laporan
            
        Returns:
            str: Path file laporan
        """
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"active_investigation_report_{timestamp}.txt"
            
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, 'w') as f:
            f.write(report_text)
            
        logger.info(f"Laporan disimpan ke: {filepath}")
        return filepath


def main():
    """
    Fungsi utama untuk menjalankan investigasi IP dari command line
    """
    parser = argparse.ArgumentParser(description='Alat Investigasi Aktif IP')
    parser.add_argument('ips', nargs='+', help='Alamat IP untuk diinvestigasi (max 5)')
    parser.add_argument('--ports', help='Port yang akan di-scan (format Nmap, misalnya "22,80,443" atau "1-1000")')
    parser.add_argument('--intensity', type=int, choices=range(1, 6), default=3, 
                        help='Level intensitas scanning (1=paling cepat/tidak invasif, 5=paling lengkap/invasif)')
    parser.add_argument('--parallel', action='store_true', help='Jalankan investigasi secara paralel')
    parser.add_argument('--output', '-o', help='Nama file output')
    parser.add_argument('--timeout', type=int, default=5, help='Timeout untuk koneksi (detik)')
    
    args = parser.parse_args()
    
    # Batasi maksimal 5 IP
    if len(args.ips) > 5:
        logger.warning("Dibatasi maksimal 5 IP. Hanya 5 IP pertama yang akan diinvestigasi.")
        args.ips = args.ips[:5]
        
    # Tampilkan peringatan untuk scan intensif
    if args.intensity >= 4:
        logger.warning("PERINGATAN: Anda menjalankan scan dengan intensitas tinggi.")
        logger.warning("Pastikan Anda memiliki izin untuk melakukan scanning terhadap target.")
        choice = input("Lanjutkan scan? (y/n): ")
        if choice.lower() != 'y':
            logger.info("Scan dibatalkan oleh pengguna.")
            return
        
    # Jalankan investigasi
    investigator = ActiveIPInvestigator(
        intensity=args.intensity,
        ports=args.ports,
        timeout=args.timeout
    )
    
    results = investigator.investigate_multiple_ips(args.ips, parallel=args.parallel)
    
    # Simpan hasil JSON
    json_file = investigator.save_results(args.output)
    
    # Buat dan simpan laporan
    report = investigator.generate_report()
    txt_file = investigator.save_report(report)
    
    # Tampilkan laporan ke stdout
    print(report)
    print(f"\nHasil disimpan di: {json_file}")
    print(f"Laporan disimpan di: {txt_file}")


if __name__ == "__main__":
    disclaimer = """
    [!] DISCLAIMER [!]
    
    Alat ini melakukan scanning aktif terhadap target.
    Pastikan Anda memiliki izin untuk melakukan scanning terhadap target.
    Penggunaan alat ini tanpa izin dapat melanggar hukum di banyak negara.
    
    Penulis tidak bertanggung jawab atas penyalahgunaan alat ini.
    
    Apakah Anda memahami dan bertanggung jawab atas penggunaan alat ini? (y/n): """
    
    choice = input(disclaimer)
    if choice.lower() != 'y':
        print("Investigasi dibatalkan.")
        sys.exit(0)
        
    main()