# 🔥 SyafaHosting School OSINT & Security Assessment Toolkit 🔥

<p align="center">
  <img src="https://img.shields.io/badge/Author-SyafaHosting-red" alt="Author">
  <img src="https://img.shields.io/badge/Version-1.0-blue" alt="Version">
  <img src="https://img.shields.io/badge/Python-3.8+-green" alt="Python">
  <img src="https://img.shields.io/badge/Status-Active-success" alt="Status">
  <img src="https://img.shields.io/badge/License-MIT-yellow" alt="License">
</p>

<p align="center">
  <strong>⚡ Infrastructure Reconnaissance & Security Assessment Toolkit ⚡</strong><br>
  <em>DNS Intelligence, Website Analysis, Network Mapping & Reporting</em>
</p>

---

## 🎯 Overview

**SyafaHosting School OSINT & Security Assessment Toolkit** adalah tool Python yang dirancang untuk melakukan pengumpulan informasi publik (OSINT), pemetaan infrastruktur jaringan, serta security assessment dasar terhadap website sekolah maupun organisasi.

Tool ini menggabungkan berbagai teknik reconnaissance seperti DNS enumeration, WHOIS lookup, subdomain discovery, website crawling, port scanning, hingga pembuatan laporan otomatis dalam format HTML dan JSON.

---

# 🚀 Features

## 🌐 DNS Intelligence

- A Record Enumeration
- AAAA Record Enumeration
- MX Record Discovery
- NS Record Discovery
- TXT Record Collection
- SOA Record Analysis
- Reverse DNS Lookup
- Infrastructure Identification

---

## 🔍 Domain Intelligence

- WHOIS Lookup
- Registrar Information
- Domain Creation Date
- Domain Expiration Date
- Name Server Discovery
- Domain Metadata Collection

---

## 🛰️ Subdomain Enumeration

- School-Oriented Wordlist
- Multi-threaded Enumeration
- Automatic IP Resolution
- Infrastructure Mapping
- Service Discovery

---

## 🛡️ Network Assessment

- Common Service Detection
- HTTP / HTTPS Detection
- SSH Discovery
- FTP Discovery
- Mail Service Detection
- Database Service Detection
- Multi-threaded Port Scanning

Supported Ports:

- 21 FTP
- 22 SSH
- 25 SMTP
- 53 DNS
- 80 HTTP
- 110 POP3
- 143 IMAP
- 443 HTTPS
- 3306 MySQL
- 5432 PostgreSQL
- 8080 HTTP Alternative
- 8443 HTTPS Alternative
- 27017 MongoDB

---

## 🕷️ Website Analysis

- Website Crawling
- URL Discovery
- Metadata Collection
- Public Email Extraction
- Public Phone Number Extraction
- Basic Content Enumeration

---

## 🏫 School Information Gathering

Automatically attempts to identify:

- NPSN
- NSS
- Accreditation Information
- School Profile Data
- Principal Information
- Student Count Information
- Public Contact Information

---

## ⚙️ Administrative Endpoint Discovery

Checks common administrative interfaces such as:

- phpMyAdmin
- Adminer
- MySQL Management Panels
- Database Management Interfaces

---

## 📊 Reporting System

Generate detailed reports in:

- JSON Format
- HTML Format

Includes:

- Scan Summary
- Infrastructure Overview
- DNS Records
- Open Ports
- Subdomains
- Website Findings
- School Information
- Endpoint Discovery Results

---

# 📦 Included Tools

## school_osint.py

Comprehensive reconnaissance and assessment tool.

### Features

- DNS Enumeration
- WHOIS Lookup
- Subdomain Discovery
- Port Scanning
- Website Crawling
- School Data Extraction
- Endpoint Discovery
- HTML Reporting
- JSON Reporting

---

## cf_bypass.py

Cloudflare and infrastructure analysis utility.

### Features

- DNS Analysis
- HTTP Header Collection
- Infrastructure Discovery
- Target Enumeration
- Network Information Gathering

---

# 🛠 Installation

## Clone Repository

```bash
git clone https://github.com/msyafa-alg/toolshck.git

cd toolshck
```

## Install Dependencies

```bash
pip install -r requirements.txt
```

---

# 🚀 Usage

## School Assessment

```bash
python school_osint.py -d sekolah.sch.id
```

Verbose Mode:

```bash
python school_osint.py -d sekolah.sch.id -v
```

Fast Mode:

```bash
python school_osint.py -d sekolah.sch.id -f
```

---

## Cloudflare Analysis

```bash
python cf_bypass.py target.com
```

---

# 📁 Output Files

Generated files:

```text
void_osint_report_target.json

void_osint_report_target.html

void_osint_target.log
```

---

# 📋 Example Report Content

- DNS Records
- WHOIS Information
- Subdomain Enumeration
- Open Ports
- Infrastructure Mapping
- Website Metadata
- Contact Information
- School Information
- Administrative Endpoints

---

# ⚡ Technical Stack

- Python 3.8+
- Requests
- BeautifulSoup4
- dnspython
- python-whois
- concurrent.futures
- urllib3

---

# ⚠ Disclaimer

This project is intended solely for:

- Educational Purposes
- Security Research
- Authorized Security Assessments
- Infrastructure Auditing

Always obtain proper authorization before scanning, testing, or assessing systems that you do not own or explicitly manage.

The author is not responsible for misuse of this software.

---

<p align="center">
  <strong>SyafaHosting Security Research Project</strong><br>
  Infrastructure Reconnaissance & Security Assessment Toolkit
</p>
