#!/usr/bin/env python3
"""
Alat Investigasi Pasif IP

Tool ini melakukan pengumpulan informasi pasif terhadap alamat IP target,
tanpa melakukan scanning aktif yang dapat memicu alert pada sistem target.

Informasi yang dikumpulkan:
- Whois
- Reverse DNS
- Geolokasi IP
- Reputasi IP (blacklist check)
- ASN & informasi organisasi
- Informasi domain terkait

Penggunaan: python passive_ip_recon.py <ip1> [ip2] [ip3] [ip4] [ip5]
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
from datetime import datetime
import requests

# Konfigurasi logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("PassiveIPRecon")

# Direktori untuk menyimpan hasil
OUTPUT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reports", "ip_recon")

# Buat direktori jika belum ada
if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)

class PassiveIPInvestigator:
    """
    Kelas untuk melakukan investigasi pasif terhadap alamat IP
    """
    
    def __init__(self, rate_limit=1.0):
        """
        Inisialisasi investigator
        
        Args:
            rate_limit (float): Delay antar request API (dalam detik)
        """
        self.rate_limit = rate_limit
        self.results = {}
        
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
            
    def get_reverse_dns(self, ip_addr):
        """
        Mendapatkan reverse DNS dari alamat IP
        
        Args:
            ip_addr (str): Alamat IP target
            
        Returns:
            dict: Hasil reverse DNS lookup
        """
        result = {
            "status": "success",
            "hostname": None,
            "error": None
        }
        
        try:
            hostname, _, _ = socket.gethostbyaddr(ip_addr)
            result["hostname"] = hostname
        except socket.herror:
            result["status"] = "not_found"
            result["error"] = "No hostname found"
        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)
            
        return result
        
    def get_geolocation(self, ip_addr):
        """
        Mendapatkan informasi geolokasi IP menggunakan API ipinfo.io
        
        Args:
            ip_addr (str): Alamat IP target
            
        Returns:
            dict: Informasi geolokasi
        """
        result = {
            "status": "success",
            "data": None,
            "error": None
        }
        
        try:
            # API gratis, rate limit diterapkan
            time.sleep(self.rate_limit)
            
            response = requests.get(f"https://ipinfo.io/{ip_addr}/json", 
                                   headers={"User-Agent": "PassiveIPInvestigator"}, 
                                   timeout=10)
            
            if response.status_code == 200:
                result["data"] = response.json()
            else:
                result["status"] = "error"
                result["error"] = f"HTTP {response.status_code}"
        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)
            
        return result
        
    def check_ip_reputation(self, ip_addr):
        """
        Memeriksa reputasi IP menggunakan AbuseIPDB API
        
        Args:
            ip_addr (str): Alamat IP target
            
        Returns:
            dict: Informasi reputasi IP
        """
        result = {
            "status": "success",
            "data": None,
            "error": None
        }
        
        try:
            # Catatan: API AbuseIPDB memerlukan API key
            # Untuk demo ini, kita mengembalikan pesan bahwa API key diperlukan
            # Dalam implementasi sebenarnya, Anda dapat mendaftar dan mendapatkan API key
            
            result["status"] = "api_key_required"
            result["data"] = {
                "message": "AbuseIPDB API key required. Register at https://www.abuseipdb.com/",
                "note": "To use the actual API, set ABUSEIPDB_API_KEY environment variable and update this function"
            }
            
            # API key implementation (uncomment jika memiliki API key)
            """
            api_key = os.environ.get("ABUSEIPDB_API_KEY")
            if not api_key:
                result["status"] = "api_key_required"
                result["error"] = "ABUSEIPDB_API_KEY environment variable not set"
                return result
                
            time.sleep(self.rate_limit)
            
            headers = {
                "Key": api_key,
                "Accept": "application/json",
                "User-Agent": "PassiveIPInvestigator"
            }
            
            params = {
                "ipAddress": ip_addr,
                "maxAgeInDays": 90
            }
            
            response = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers=headers,
                params=params,
                timeout=10
            )
            
            if response.status_code == 200:
                result["data"] = response.json().get("data", {})
            else:
                result["status"] = "error"
                result["error"] = f"HTTP {response.status_code}: {response.text}"
            """
        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)
            
        return result
        
    def get_shodan_info(self, ip_addr):
        """
        Mendapatkan informasi IP dari Shodan API
        
        Args:
            ip_addr (str): Alamat IP target
            
        Returns:
            dict: Informasi dari Shodan
        """
        result = {
            "status": "success",
            "data": None,
            "error": None
        }
        
        try:
            # Catatan: API Shodan memerlukan API key
            # Untuk demo ini, kita mengembalikan pesan bahwa API key diperlukan
            
            result["status"] = "api_key_required"
            result["data"] = {
                "message": "Shodan API key required. Register at https://shodan.io/",
                "note": "To use the actual API, set SHODAN_API_KEY environment variable and update this function"
            }
            
            # API key implementation (uncomment jika memiliki API key)
            """
            api_key = os.environ.get("SHODAN_API_KEY")
            if not api_key:
                result["status"] = "api_key_required"
                result["error"] = "SHODAN_API_KEY environment variable not set"
                return result
                
            time.sleep(self.rate_limit)
            
            response = requests.get(
                f"https://api.shodan.io/shodan/host/{ip_addr}?key={api_key}",
                headers={"User-Agent": "PassiveIPInvestigator"},
                timeout=10
            )
            
            if response.status_code == 200:
                result["data"] = response.json()
            elif response.status_code == 404:
                result["status"] = "not_found"
                result["error"] = "IP not found in Shodan database"
            else:
                result["status"] = "error"
                result["error"] = f"HTTP {response.status_code}: {response.text}"
            """
        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)
            
        return result
        
    def get_whois_info(self, ip_addr):
        """
        Mendapatkan informasi WHOIS dari alamat IP
        
        Args:
            ip_addr (str): Alamat IP target
            
        Returns:
            dict: Informasi WHOIS
        """
        result = {
            "status": "success",
            "data": None,
            "error": None
        }
        
        try:
            # Gunakan RDAP API (pengganti WHOIS modern)
            time.sleep(self.rate_limit)
            
            response = requests.get(
                f"https://rdap.arin.net/registry/ip/{ip_addr}",
                headers={"Accept": "application/json", "User-Agent": "PassiveIPInvestigator"},
                timeout=10
            )
            
            if response.status_code == 200:
                result["data"] = response.json()
            else:
                result["status"] = "error"
                result["error"] = f"HTTP {response.status_code}"
        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)
            
        return result
        
    def investigate_ip(self, ip_addr):
        """
        Melakukan investigasi pasif terhadap alamat IP
        
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
        
        # Kumpulkan semua informasi
        result = {
            "ip": ip_addr,
            "timestamp": datetime.now().isoformat(),
            "reverse_dns": self.get_reverse_dns(ip_addr),
            "geolocation": self.get_geolocation(ip_addr),
            "reputation": self.check_ip_reputation(ip_addr),
            "shodan": self.get_shodan_info(ip_addr),
            "whois": self.get_whois_info(ip_addr)
        }
        
        # Tambahkan ke hasil
        self.results[ip_addr] = result
        
        logger.info(f"Investigasi selesai untuk IP: {ip_addr}")
        return result
        
    def investigate_multiple_ips(self, ip_list, parallel=True):
        """
        Menjalankan investigasi terhadap beberapa IP
        
        Args:
            ip_list (list): Daftar alamat IP yang akan diinvestigasi
            parallel (bool): Jalankan penyelidikan secara paralel
            
        Returns:
            dict: Hasil investigasi untuk semua IP
        """
        self.results = {}
        
        if parallel and len(ip_list) > 1:
            # Jalankan investigasi secara paralel
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(5, len(ip_list))) as executor:
                executor.map(self.investigate_ip, ip_list)
        else:
            # Jalankan investigasi secara sekuensial
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
            filename = f"ip_investigation_{timestamp}.json"
            
        filepath = os.path.join(OUTPUT_DIR, filename)
        
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
        report.append("=" * 50)
        report.append("LAPORAN INVESTIGASI PASIF IP")
        report.append("=" * 50)
        report.append(f"Waktu Laporan: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Jumlah IP Diinvestigasi: {len(self.results)}")
        report.append("")
        
        for ip, data in self.results.items():
            report.append("-" * 50)
            report.append(f"IP: {ip}")
            report.append("-" * 50)
            
            # Reverse DNS
            if data["reverse_dns"]["status"] == "success":
                report.append(f"Hostname: {data['reverse_dns']['hostname']}")
            else:
                report.append(f"Hostname: Tidak ditemukan")
                
            # Geolokasi
            geo = data["geolocation"]
            if geo["status"] == "success" and geo["data"]:
                g = geo["data"]
                location = []
                if "city" in g:
                    location.append(g["city"])
                if "region" in g:
                    location.append(g["region"])
                if "country" in g:
                    location.append(g["country"])
                
                report.append(f"Lokasi: {', '.join(location)}")
                if "org" in g:
                    report.append(f"Organisasi: {g['org']}")
                if "asn" in g:
                    report.append(f"ASN: {g['asn']}")
            else:
                report.append("Geolokasi: Informasi tidak tersedia")
                
            # Reputasi
            rep = data["reputation"]
            if rep["status"] == "api_key_required":
                report.append("Reputasi: API key diperlukan")
            elif rep["status"] == "success" and rep["data"]:
                report.append("Reputasi: Informasi tersedia (lihat file JSON)")
            else:
                report.append("Reputasi: Informasi tidak tersedia")
                
            # Shodan
            shodan = data["shodan"]
            if shodan["status"] == "api_key_required":
                report.append("Shodan: API key diperlukan")
            elif shodan["status"] == "success" and shodan["data"]:
                report.append("Shodan: Informasi tersedia (lihat file JSON)")
            else:
                report.append("Shodan: Informasi tidak tersedia")
                
            # WHOIS
            whois = data["whois"]
            if whois["status"] == "success" and whois["data"]:
                report.append("WHOIS: Informasi tersedia (lihat file JSON)")
                if "name" in whois["data"]:
                    report.append(f"Registrar: {whois['data']['name']}")
            else:
                report.append("WHOIS: Informasi tidak tersedia")
                
            report.append("")
            
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
            filename = f"ip_investigation_report_{timestamp}.txt"
            
        filepath = os.path.join(OUTPUT_DIR, filename)
        
        with open(filepath, 'w') as f:
            f.write(report_text)
            
        logger.info(f"Laporan disimpan ke: {filepath}")
        return filepath


def main():
    """
    Fungsi utama untuk menjalankan investigasi IP dari command line
    """
    parser = argparse.ArgumentParser(description='Alat Investigasi Pasif IP')
    parser.add_argument('ips', nargs='+', help='Alamat IP untuk diinvestigasi (max 5)')
    parser.add_argument('--parallel', action='store_true', help='Jalankan investigasi secara paralel')
    parser.add_argument('--output', '-o', help='Nama file output')
    parser.add_argument('--rate-limit', type=float, default=1.0, help='Delay antar API request (detik)')
    
    args = parser.parse_args()
    
    # Batasi maksimal 5 IP
    if len(args.ips) > 5:
        logger.warning("Dibatasi maksimal 5 IP. Hanya 5 IP pertama yang akan diinvestigasi.")
        args.ips = args.ips[:5]
        
    # Jalankan investigasi
    investigator = PassiveIPInvestigator(rate_limit=args.rate_limit)
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
    main()