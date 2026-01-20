#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# PROJECT VOID OSINT v1.0 - ADVANCED SCHOOL INTELLIGENCE SYSTEM
# Author: HackerIndonet
# Matrix Level: ALPHA OMEGA
# Special: Full Spectrum Reconnaissance

import requests
import json
import socket
import whois
import dns.resolver
import dns.reversename
import re
import sys
import argparse
import time
import random
import threading
import queue
import os
import hashlib
import ssl
import urllib3
import ipaddress
from datetime import datetime, timedelta
from urllib.parse import urlparse, urljoin, quote
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup
import subprocess
import sqlite3
import csv
import pickle
import base64
import zlib
import gzip
import bz2
import lzma
import struct
import binascii
import hmac
import secrets
import string
import math
import statistics
import itertools
import collections
import functools
import inspect
import typing
import warnings
import traceback
import logging
import getpass
import platform
import shutil
import tempfile
import pathlib
import glob
import fnmatch
import stat
import pprint
import textwrap
import shlex
import configparser

# Disable warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class MatrixColors:
    """ANSI Color Codes for Matrix Style"""
    GREEN = '\033[92m'
    CYAN = '\033[96m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    WHITE = '\033[97m'
    BLACK = '\033[90m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    
    # Matrix Rain Effect
    MATRIX_GREEN = '\033[38;5;46m'
    MATRIX_DARK_GREEN = '\033[38;5;22m'
    MATRIX_BLACK = '\033[38;5;232m'

class JSONEncoder(json.JSONEncoder):
    """Custom JSON encoder to handle non-serializable objects"""
    def default(self, obj):
        if isinstance(obj, set):
            return list(obj)
        elif isinstance(obj, datetime):
            return obj.isoformat()
        elif hasattr(obj, '__dict__'):
            return obj.__dict__
        return super().default(obj)

class AdvancedSchoolOSINT:
    """Advanced OSINT Engine for School Intelligence"""
    
    def __init__(self, target_domain):
        self.target_domain = target_domain
        self.results = {
            'basic_info': {},
            'network_intelligence': {},
            'security_analysis': {},
            'personnel_data': {},
            'infrastructure_map': {},
            'vulnerabilities': {},
            'metadata': {}
        }
        
        # User Agents Rotation
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36'
        ]
        
        # School-specific wordlists
        self.school_subdomains = [
            'www', 'mail', 'ftp', 'webmail', 'portal', 'e-learning', 'elearning',
            'siswa', 'student', 'guru', 'teacher', 'dosen', 'lecturer', 'akademik',
            'academic', 'perpus', 'library', 'lab', 'laboratory', 'sso', 'auth',
            'api', 'dev', 'test', 'staging', 'backup', 'db', 'database', 'sql',
            'admin', 'administrator', 'cpanel', 'whm', 'webdisk', 'webmin',
            'dapodik', 'simbel', 'simak', 'psb', 'ppdb', 'pmb', 'penerimaan',
            'admission', 'registrasi', 'registration', 'nilai', 'score', 'raport',
            'report', 'spp', 'payment', 'pembayaran', 'keuangan', 'finance',
            'bkd', 'hrd', 'sdm', 'humas', 'public', 'info', 'news', 'berita',
            'blog', 'forum', 'discussion', 'chat', 'support', 'help', 'faq'
        ]
        
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': random.choice(self.user_agents)})
        self.session.verify = False
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format=f'{MatrixColors.MATRIX_GREEN}[%(asctime)s] %(levelname)s: %(message)s{MatrixColors.ENDC}',
            handlers=[
                logging.FileHandler(f'void_osint_{target_domain}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def display_banner(self):
        """Display Matrix-style banner"""
        banner = f"""
{MatrixColors.MATRIX_GREEN}
╔══════════════════════════════════════════════════════════════════════╗
║              {MatrixColors.WHITE}PROJECT VOID OSINT v1.0 - ADVANCED MATRIX{MatrixColors.MATRIX_GREEN}              ║
║              {MatrixColors.WHITE}SCHOOL INTELLIGENCE GATHERING SYSTEM{MatrixColors.MATRIX_GREEN}                  ║
║                                                                      ║
║  {MatrixColors.CYAN}Target:{MatrixColors.WHITE} {self.target_domain:50}{MatrixColors.MATRIX_GREEN}  ║
║  {MatrixColors.CYAN}Mode:{MatrixColors.WHITE} Full Spectrum Reconnaissance{MatrixColors.MATRIX_GREEN:26}          ║
║  {MatrixColors.CYAN}Date:{MatrixColors.WHITE} {datetime.now().strftime("%Y-%m-%d %H:%M:%S"):40}{MatrixColors.MATRIX_GREEN}  ║
║  {MatrixColors.CYAN}Author:{MatrixColors.WHITE} HackerIndonet{MatrixColors.MATRIX_GREEN:36}                       ║
║  {MatrixColors.CYAN}Release:{MatrixColors.WHITE} 20 Januari{MatrixColors.MATRIX_GREEN:38}                         ║
╚══════════════════════════════════════════════════════════════════════╝
{MatrixColors.ENDC}
"""
        print(banner)

    def get_random_headers(self):
        """Get random headers for request rotation"""
        return {
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0',
            'TE': 'Trailers'
        }

    def get_dns_records(self):
        """Comprehensive DNS reconnaissance"""
        self.logger.info("Starting DNS reconnaissance...")
        
        dns_results = {
            'A': [], 'AAAA': [], 'MX': [], 'NS': [], 'TXT': [], 'CNAME': [],
            'SOA': [], 'PTR': [], 'SRV': [], 'CAA': []
        }
        
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(self.target_domain, record_type)
                dns_results[record_type] = [str(rdata) for rdata in answers]
                self.logger.info(f"Found {record_type}: {dns_results[record_type]}")
            except Exception as e:
                dns_results[record_type] = []
        
        # Reverse DNS lookup if IP is found
        if dns_results['A']:
            for ip in dns_results['A']:
                try:
                    reverse = dns.reversename.from_address(ip)
                    ptr_records = dns.resolver.resolve(reverse, 'PTR')
                    dns_results['PTR'] = [str(ptr) for ptr in ptr_records]
                except:
                    pass
        
        self.results['network_intelligence']['dns_records'] = dns_results
        return dns_results

    def get_whois_comprehensive(self):
        """Comprehensive WHOIS analysis"""
        self.logger.info("Performing WHOIS analysis...")
        
        whois_data = {
            'registrar': None,
            'creation_date': None,
            'expiration_date': None,
            'name_servers': [],
            'registrant': {},
            'raw': None
        }
        
        try:
            domain_info = whois.whois(self.target_domain)
            
            # Extract structured data
            whois_data.update({
                'registrar': domain_info.registrar,
                'creation_date': str(domain_info.creation_date) if domain_info.creation_date else None,
                'expiration_date': str(domain_info.expiration_date) if domain_info.expiration_date else None,
                'name_servers': list(domain_info.name_servers) if domain_info.name_servers else [],
                'registrant': {
                    'name': domain_info.registrant_name,
                    'organization': domain_info.registrant_organization,
                    'country': domain_info.registrant_country,
                    'email': domain_info.registrant_email
                },
                'raw': str(domain_info)
            })
            
            self.logger.info(f"WHOIS data retrieved: {whois_data['registrar']}")
            
        except Exception as e:
            self.logger.error(f"WHOIS error: {str(e)}")
            whois_data['raw'] = f"Error: {str(e)}"
        
        self.results['basic_info']['whois'] = whois_data
        return whois_data

    def enumerate_subdomains_advanced(self):
        """Advanced subdomain enumeration with multiple techniques"""
        self.logger.info("Starting advanced subdomain enumeration...")
        
        found_subdomains = []
        
        # Technique 1: Brute force with school-specific wordlist
        self.logger.info("Technique 1: Brute forcing subdomains...")
        
        def brute_force_subdomain(sub):
            for subdomain in [sub, f"{sub}2", f"{sub}3", f"{sub}-test"]:
                full_domain = f"{subdomain}.{self.target_domain}"
                try:
                    ip = socket.gethostbyname(full_domain)
                    found_subdomains.append({'domain': full_domain, 'ip': ip})
                    self.logger.info(f"Found: {full_domain} -> {ip}")
                except:
                    continue
        
        # Multi-threaded brute force
        with ThreadPoolExecutor(max_workers=50) as executor:
            executor.map(brute_force_subdomain, self.school_subdomains)
        
        self.results['network_intelligence']['subdomains'] = found_subdomains
        return found_subdomains

    def scan_ports_comprehensive(self, ip_address):
        """Comprehensive port scanning"""
        if not ip_address:
            return {}
            
        self.logger.info(f"Starting port scan for {ip_address}...")
        
        # School-specific ports
        school_ports = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            465: 'SMTPS',
            587: 'SMTP Submission',
            993: 'IMAPS',
            995: 'POP3S',
            2082: 'cPanel',
            2083: 'cPanel SSL',
            2086: 'WHM',
            2087: 'WHM SSL',
            2095: 'Webmail',
            2096: 'Webmail SSL',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            8080: 'HTTP Proxy',
            8443: 'HTTPS Alt',
            8888: 'HTTP Alt',
            27017: 'MongoDB'
        }
        
        open_ports = {}
        
        def scan_port(port, service):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip_address, port))
                if result == 0:
                    open_ports[port] = {'service': service, 'banner': None}
                    self.logger.info(f"Port {port} ({service}) is OPEN")
                sock.close()
            except:
                pass
        
        # Multi-threaded port scanning
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(scan_port, port, service) for port, service in school_ports.items()]
            for future in as_completed(futures):
                future.result()
        
        self.results['security_analysis']['open_ports'] = open_ports
        return open_ports

    def crawl_website(self, url):
        """Advanced website crawling"""
        self.logger.info(f"Crawling website: {url}")
        
        crawled_data = {
            'urls': [],
            'forms': [],
            'emails': [],
            'phones': [],
            'metadata': {}
        }
        
        try:
            response = self.session.get(url, headers=self.get_random_headers(), timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract all links
            urls_set = set()
            for link in soup.find_all('a', href=True):
                href = link['href']
                if href.startswith('http'):
                    urls_set.add(href)
                elif href.startswith('/'):
                    full_url = urljoin(url, href)
                    urls_set.add(full_url)
            
            crawled_data['urls'] = list(urls_set)[:50]  # Limit to 50 URLs
            
            # Extract metadata
            meta_tags = soup.find_all('meta')
            for meta in meta_tags:
                name = meta.get('name', meta.get('property', ''))
                content = meta.get('content', '')
                if name and content:
                    crawled_data['metadata'][name] = content
            
            # Extract emails and phones
            text_content = soup.get_text()
            email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
            phone_pattern = r'[\+\(]?[1-9][0-9 .\-\(\)]{8,}[0-9]'
            
            crawled_data['emails'] = list(set(re.findall(email_pattern, text_content)))
            crawled_data['phones'] = list(set(re.findall(phone_pattern, text_content)))
            
        except Exception as e:
            self.logger.error(f"Crawling error: {str(e)}")
        
        self.results['infrastructure_map']['crawled_data'] = crawled_data
        return crawled_data

    def find_school_specific_data(self):
        """Find school-specific information patterns"""
        self.logger.info("Searching for school-specific data...")
        
        school_data = {
            'npsn': None,
            'nss': None,
            'nds': None,
            'akreditasi': None,
            'nama_kepala_sekolah': None,
            'nama_wakil_kepala': [],
            'jumlah_siswa': None,
            'jumlah_kelas': None,
            'jurusan': [],
            'kontak': {}
        }
        
        # Try to access common school data endpoints
        common_school_pages = [
            f"https://{self.target_domain}/profil",
            f"https://{self.target_domain}/tentang",
            f"https://{self.target_domain}/about",
            f"https://{self.target_domain}/sejarah",
            f"https://{self.target_domain}/visi-misi",
            f"https://{self.target_domain}/data",
            f"https://{self.target_domain}/informasi",
            f"https://{self.target_domain}/index.php",
            f"https://{self.target_domain}/"
        ]
        
        for page in common_school_pages:
            try:
                response = self.session.get(page, headers=self.get_random_headers(), timeout=5)
                if response.status_code == 200:
                    content = response.text.lower()
                    
                    # Search for NPSN
                    npsn_patterns = [
                        r'npsn[:\s]*([0-9]{8})',
                        r'nomor pokok sekolah nasional[:\s]*([0-9]{8})',
                        r'kode sekolah[:\s]*([0-9]{8})'
                    ]
                    
                    for pattern in npsn_patterns:
                        match = re.search(pattern, content)
                        if match:
                            school_data['npsn'] = match.group(1)
                            break
                    
                    # Search for NSS
                    nss_pattern = r'nss[:\s]*([0-9\.]+)'
                    match = re.search(nss_pattern, content)
                    if match:
                        school_data['nss'] = match.group(1)
                    
                    # Search for accreditation
                    akreditasi_patterns = [
                        r'akreditasi[:\s]*([a-z]{1,2})',
                        r'peringkat akreditasi[:\s]*([a-z]{1,2})',
                        r'terakreditasi[:\s]*([a-z]{1,2})'
                    ]
                    
                    for pattern in akreditasi_patterns:
                        match = re.search(pattern, content)
                        if match:
                            school_data['akreditasi'] = match.group(1).upper()
                            break
                    
                    # Search for school principal
                    kepala_patterns = [
                        r'kepala sekolah[:\s]*([a-z\.\s]+)[\.<]',
                        r'kepsek[:\s]*([a-z\.\s]+)[\.<]',
                        r'headmaster[:\s]*([a-z\.\s]+)[\.<]'
                    ]
                    
                    for pattern in kepala_patterns:
                        matches = re.findall(pattern, content)
                        if matches:
                            school_data['nama_kepala_sekolah'] = matches[0].strip().title()
                            break
                    
                    # Search for student count
                    siswa_patterns = [
                        r'jumlah siswa[:\s]*([0-9,\.]+)',
                        r'siswa[:\s]*([0-9,\.]+)[\s]*(?:orang|siswa)',
                        r'peserta didik[:\s]*([0-9,\.]+)'
                    ]
                    
                    for pattern in siswa_patterns:
                        match = re.search(pattern, content)
                        if match:
                            school_data['jumlah_siswa'] = match.group(1).replace('.', '').replace(',', '')
                            break
                    
                    # Extract contact information
                    email_pattern = r'[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}'
                    emails = re.findall(email_pattern, content)
                    if emails:
                        school_data['kontak']['emails'] = list(set(emails))
                    
                    phone_pattern = r'[\+\(]?[1-9][0-9 .\-\(\)]{8,}[0-9]'
                    phones = re.findall(phone_pattern, content)
                    if phones:
                        school_data['kontak']['phones'] = list(set(phones))
                    
            except Exception as e:
                self.logger.debug(f"Error accessing {page}: {str(e)}")
                continue
        
        self.results['basic_info']['school_data'] = school_data
        return school_data

    def find_database_endpoints(self):
        """Find database management endpoints"""
        self.logger.info("Searching for database endpoints...")
        
        db_endpoints = []
        common_db_paths = [
            '/phpmyadmin/', '/mysql/', '/pma/', '/dbadmin/', '/database/',
            '/adminer/', '/db/', '/sql/', '/dba/', '/myadmin/', '/webdb/',
            '/phpMyAdmin/', '/phpmyadmin2/', '/phpmyadmin3/', '/phpmyadmin4/',
            '/administrator/phpmyadmin/', '/_phpmyadmin/', '/_database/'
        ]
        
        base_urls = [
            f"http://{self.target_domain}",
            f"https://{self.target_domain}",
            f"http://www.{self.target_domain}",
            f"https://www.{self.target_domain}"
        ]
        
        def check_db_endpoint(url):
            try:
                response = self.session.get(url, headers=self.get_random_headers(), timeout=3)
                if response.status_code == 200:
                    # Check for database indicators in response
                    db_indicators = ['phpmyadmin', 'mysql', 'database', 'sql', 'pma']
                    if any(indicator in response.text.lower() for indicator in db_indicators):
                        db_endpoints.append({
                            'url': url,
                            'status_code': response.status_code
                        })
                        self.logger.warning(f"Database endpoint found: {url}")
            except:
                pass
        
        # Check all combinations
        for base_url in base_urls:
            for path in common_db_paths:
                url = f"{base_url}{path}"
                check_db_endpoint(url)
        
        self.results['vulnerabilities']['database_endpoints'] = db_endpoints
        return db_endpoints

    def generate_report(self):
        """Generate comprehensive report"""
        self.logger.info("Generating comprehensive report...")
        
        # Convert all sets to lists for JSON serialization
        self._clean_results_for_json()
        
        report = {
            'scan_summary': {
                'target': self.target_domain,
                'scan_date': datetime.now().isoformat(),
                'findings_count': {
                    'subdomains': len(self.results['network_intelligence'].get('subdomains', [])),
                    'open_ports': len(self.results['security_analysis'].get('open_ports', {})),
                    'database_endpoints': len(self.results['vulnerabilities'].get('database_endpoints', [])),
                    'school_data_points': len(self.results['basic_info'].get('school_data', {}))
                }
            },
            'detailed_findings': self.results
        }
        
        # Save report to JSON
        filename = f"void_osint_report_{self.target_domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=4, ensure_ascii=False, cls=JSONEncoder)
        
        # Save report to HTML
        html_filename = filename.replace('.json', '.html')
        self.generate_html_report(report, html_filename)
        
        self.logger.info(f"Report saved to {filename}")
        return filename

    def _clean_results_for_json(self):
        """Convert all non-serializable objects to serializable ones"""
        def clean_obj(obj):
            if isinstance(obj, dict):
                return {k: clean_obj(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [clean_obj(item) for item in obj]
            elif isinstance(obj, set):
                return list(obj)
            elif isinstance(obj, (datetime, timedelta)):
                return str(obj)
            else:
                return obj
        
        self.results = clean_obj(self.results)

    def generate_html_report(self, report, filename):
        """Generate HTML report"""
        try:
            # Convert report to JSON string for display
            report_json = json.dumps(report, indent=2, ensure_ascii=False, cls=JSONEncoder)
            
            html_template = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VOID OSINT Report - {self.target_domain}</title>
    <style>
        body {{
            font-family: 'Courier New', monospace;
            background: #000;
            color: #0f0;
            margin: 0;
            padding: 20px;
        }}
        .matrix-header {{
            background: #000;
            padding: 20px;
            border: 2px solid #0f0;
            margin-bottom: 20px;
        }}
        .matrix-title {{
            color: #0f0;
            font-size: 24px;
            text-align: center;
            text-shadow: 0 0 10px #0f0;
        }}
        .section {{
            border: 1px solid #0f0;
            padding: 15px;
            margin: 10px 0;
            background: rgba(0, 255, 0, 0.05);
        }}
        .finding {{
            color: #fff;
            margin: 5px 0;
            padding: 5px;
            border-left: 3px solid #0f0;
        }}
        .critical {{
            color: #f00;
            font-weight: bold;
        }}
        .warning {{
            color: #ff0;
        }}
        .info {{
            color: #0ff;
        }}
        pre {{
            background: #111;
            padding: 10px;
            border: 1px solid #0f0;
            overflow-x: auto;
            color: #0f0;
            max-height: 400px;
            overflow-y: auto;
            white-space: pre-wrap;
            word-wrap: break-word;
        }}
        .summary-box {{
            background: rgba(0, 255, 0, 0.1);
            padding: 10px;
            margin: 10px 0;
            border: 1px solid #0f0;
        }}
    </style>
</head>
<body>
    <div class="matrix-header">
        <div class="matrix-title">PROJECT VOID OSINT v1.0</div>
        <div style="text-align: center; color: #0f0;">Advanced School Intelligence Report</div>
        <div style="text-align: center; color: #0f0;">Target: {self.target_domain}</div>
        <div style="text-align: center; color: #0f0;">Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
    </div>
    
    <div class="section">
        <h2>📊 Scan Summary</h2>
        <div class="summary-box">
            <div class="finding"><strong>Target Domain:</strong> {report['scan_summary']['target']}</div>
            <div class="finding"><strong>Scan Date:</strong> {report['scan_summary']['scan_date']}</div>
            <div class="finding"><strong>Subdomains Found:</strong> {report['scan_summary']['findings_count']['subdomains']}</div>
            <div class="finding"><strong>Open Ports:</strong> {report['scan_summary']['findings_count']['open_ports']}</div>
            <div class="finding"><strong>Database Endpoints:</strong> {report['scan_summary']['findings_count']['database_endpoints']}</div>
            <div class="finding"><strong>School Data Points:</strong> {report['scan_summary']['findings_count']['school_data_points']}</div>
        </div>
    </div>
    
    <div class="section">
        <h2>🏫 School Information</h2>
        <pre>{json.dumps(report['detailed_findings']['basic_info'].get('school_data', {}), indent=2, ensure_ascii=False)}</pre>
    </div>
    
    <div class="section">
        <h2>🌐 Network Intelligence</h2>
        <div class="finding"><strong>Subdomains Found:</strong> {len(report['detailed_findings']['network_intelligence'].get('subdomains', []))}</div>
        <pre>{json.dumps(report['detailed_findings']['network_intelligence'], indent=2, ensure_ascii=False)}</pre>
    </div>
    
    <div class="section">
        <h2>🔓 Security Analysis</h2>
        <div class="finding"><strong>Open Ports:</strong> {len(report['detailed_findings']['security_analysis'].get('open_ports', {}))}</div>
        <pre>{json.dumps(report['detailed_findings']['security_analysis'], indent=2, ensure_ascii=False)}</pre>
    </div>
    
    <div class="section">
        <h2>⚠️ Database Endpoints</h2>
        <div class="finding"><strong>Found:</strong> {len(report['detailed_findings']['vulnerabilities'].get('database_endpoints', []))}</div>
        <pre>{json.dumps(report['detailed_findings']['vulnerabilities'], indent=2, ensure_ascii=False)}</pre>
    </div>
    
    <div class="section">
        <h2>📈 Infrastructure Map</h2>
        <pre>{json.dumps(report['detailed_findings']['infrastructure_map'], indent=2, ensure_ascii=False)}</pre>
    </div>
    
    <div style="text-align: center; margin-top: 30px; color: #0f0; font-size: 12px;">
        Generated by HackerIndonet | Project VOID OSINT v1.0 | Release: 20 Januari
    </div>
</body>
</html>
"""
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(html_template)
                
        except Exception as e:
            self.logger.error(f"Error generating HTML report: {str(e)}")
            # Create simple HTML report
            simple_html = f"""
<!DOCTYPE html>
<html>
<head><title>VOID OSINT Report - {self.target_domain}</title></head>
<body>
    <h1>VOID OSINT Report - {self.target_domain}</h1>
    <p>Scan completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    <p>Error generating detailed report: {str(e)}</p>
</body>
</html>
"""
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(simple_html)

    def run_full_scan(self):
        """Execute full spectrum scan"""
        start_time = time.time()
        
        self.display_banner()
        
        try:
            # Phase 1: Basic Reconnaissance
            self.logger.info("=== PHASE 1: BASIC RECONNAISSANCE ===")
            self.get_dns_records()
            self.get_whois_comprehensive()
            
            # Phase 2: Network Mapping
            self.logger.info("=== PHASE 2: NETWORK MAPPING ===")
            self.enumerate_subdomains_advanced()
            
            # Get main IP for port scanning
            try:
                main_ip = socket.gethostbyname(self.target_domain)
                self.scan_ports_comprehensive(main_ip)
            except Exception as e:
                self.logger.error(f"Cannot get IP for port scanning: {str(e)}")
            
            # Phase 3: Website Analysis
            self.logger.info("=== PHASE 3: WEBSITE ANALYSIS ===")
            self.crawl_website(f"https://{self.target_domain}")
            
            # Phase 4: School-Specific Intelligence
            self.logger.info("=== PHASE 4: SCHOOL-SPECIFIC INTELLIGENCE ===")
            self.find_school_specific_data()
            
            # Phase 5: Vulnerability Assessment
            self.logger.info("=== PHASE 5: VULNERABILITY ASSESSMENT ===")
            self.find_database_endpoints()
            
            # Phase 6: Report Generation
            self.logger.info("=== PHASE 6: REPORT GENERATION ===")
            report_file = self.generate_report()
            
            scan_duration = time.time() - start_time
            
            print(f"\n{MatrixColors.MATRIX_GREEN}{'='*80}{MatrixColors.ENDC}")
            print(f"{MatrixColors.WHITE}🎯 SCAN COMPLETED SUCCESSFULLY{MatrixColors.ENDC}")
            print(f"{MatrixColors.CYAN}⏱️  Duration: {scan_duration:.2f} seconds{MatrixColors.ENDC}")
            print(f"{MatrixColors.GREEN}📁 JSON Report: {report_file}{MatrixColors.ENDC}")
            print(f"{MatrixColors.GREEN}📄 HTML Report: {report_file.replace('.json', '.html')}{MatrixColors.ENDC}")
            print(f"{MatrixColors.YELLOW}🔍 Findings Summary:{MatrixColors.ENDC}")
            print(f"   • Subdomains: {len(self.results['network_intelligence'].get('subdomains', []))}")
            print(f"   • Open Ports: {len(self.results['security_analysis'].get('open_ports', {}))}")
            print(f"   • School Data Points: {len(self.results['basic_info'].get('school_data', {}))}")
            print(f"   • Database Endpoints: {len(self.results['vulnerabilities'].get('database_endpoints', []))}")
            
            # Display key findings
            school_data = self.results['basic_info'].get('school_data', {})
            if school_data.get('npsn'):
                print(f"{MatrixColors.GREEN}   • NPSN: {school_data['npsn']}{MatrixColors.ENDC}")
            if school_data.get('nama_kepala_sekolah'):
                print(f"{MatrixColors.GREEN}   • Kepala Sekolah: {school_data['nama_kepala_sekolah']}{MatrixColors.ENDC}")
            if school_data.get('akreditasi'):
                print(f"{MatrixColors.GREEN}   • Akreditasi: {school_data['akreditasi']}{MatrixColors.ENDC}")
            
            print(f"{MatrixColors.MATRIX_GREEN}{'='*80}{MatrixColors.ENDC}")
            
            return True
            
        except KeyboardInterrupt:
            self.logger.warning("Scan interrupted by user")
            print(f"\n{MatrixColors.RED}[!] Scan interrupted by user{MatrixColors.ENDC}")
            return False
        except Exception as e:
            self.logger.error(f"Scan failed: {str(e)}")
            traceback.print_exc()
            return False

def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(description='PROJECT VOID OSINT v1.0 - Advanced School Intelligence System')
    parser.add_argument('-d', '--domain', required=True, help='Target domain (e.g., sekolah.sch.id)')
    parser.add_argument('-o', '--output', help='Output directory (default: current directory)')
    parser.add_argument('-f', '--fast', action='store_true', help='Fast scan mode (limited checks)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Create OSINT engine
    osint_engine = AdvancedSchoolOSINT(args.domain)
    
    # Run full scan
    success = osint_engine.run_full_scan()
    
    if success:
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == "__main__":
    main()
