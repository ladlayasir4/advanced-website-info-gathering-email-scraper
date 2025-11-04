import asyncio
import aiohttp
import requests
import urllib3
from bs4 import BeautifulSoup
import urllib.parse
from collections import deque, defaultdict
import re
import json
import time
import threading
from concurrent.futures import ThreadPoolExecutor
import dns.resolver
import socket
import ssl
import whois
import argparse
import sys
import os
from datetime import datetime, timezone
import logging
from typing import Set, Dict, List, Tuple, Optional
import hashlib
import base64
import pandas as pd
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
import ipaddress
import random
import string
from pathlib import Path
import traceback

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class YasirUltimateReconSystem:
    """
    YASIR ABBAS - ULTIMATE GOVERNMENT RED TEAM INTELLIGENCE SYSTEM
    ULTIMATE LORD LEVEL - COMPLETE STEALTH & ANONYMITY
    FOR EDUCATIONAL PURPOSES ONLY
    """
    
    def __init__(self, target_url: str, operation_name: str = "OPERATION_SPECTRE"):
        self.target_url = self.normalize_url(target_url)
        self.operation_name = operation_name
        self.session_id = hashlib.sha256(f"{operation_name}_{datetime.now(timezone.utc).isoformat()}".encode()).hexdigest()[:16]
        self.operator_name = "Yasir Abbas"
        self.usage_notice = "FOR EDUCATIONAL AND AUTHORIZED TESTING PURPOSES ONLY"
        
        # Enhanced data storage with source tracking
        self.valid_emails: Dict[str, List[str]] = {}  # email -> [sources]
        self.valid_phone_numbers: Dict[str, List[str]] = {}
        self.social_media: Dict[str, Dict[str, List[str]]] = defaultdict(lambda: defaultdict(list))
        self.sensitive_documents: Dict[str, List[str]] = {}
        self.critical_subdomains: Dict[str, List[str]] = {}
        self.admin_directories: Dict[str, List[str]] = {}
        self.sensitive_js_files: Dict[str, List[str]] = {}
        self.critical_api_endpoints: Dict[str, List[str]] = {}
        self.technologies: Dict[str, Dict] = {}
        self.vulnerabilities: List[Dict] = []
        self.exposed_data: List[Dict] = []
        self.security_misconfigs: List[Dict] = []
        self.whois_data: Dict = {}
        self.ssl_data: Dict = {}
        self.network_info: Dict = {}
        self.sensitive_info_found: List[Dict] = []
        
        # Advanced tracking
        self.scraped_urls: Set[str] = set()
        self.url_queue = deque()
        self.url_queue.append(self.target_url)
        
        # Elite Configuration
        self.config = {
            'max_urls': 2000,
            'max_depth': 8,
            'timeout': 20,
            'concurrent_requests': 50,
            'stealth_mode': True,
            'user_agents': self.load_ultimate_user_agents(),
            'delay_range': (0.3, 1.2),
            'retry_attempts': 1,
        }
        
        # Ultimate patterns
        self.patterns = self.load_ultimate_patterns()
        
        # Performance tracking
        self.requests_made = 0
        self.start_time = None
        
        self.setup_ultimate_logging()
        self.setup_signal_handlers()
    
    def load_ultimate_user_agents(self) -> List[str]:
        """Load ultimate rotating user agents for maximum anonymity"""
        return [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1',
            'Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
            'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
            'Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)',
        ]
    
    def load_ultimate_patterns(self) -> Dict:
        """Load ultimate patterns for elite intelligence"""
        return {
            'sensitive_keywords': [
                'admin', 'administrator', 'login', 'secure', 'auth', 'authentication',
                'config', 'configuration', 'backup', 'database', 'sql', 'db',
                'api', 'rest', 'graphql', 'endpoint', 'internal', 'private',
                'secret', 'key', 'password', 'credential', 'token', 'session',
                'dashboard', 'portal', 'control', 'manage', 'adminpanel',
                'wp-admin', 'phpmyadmin', 'cpanel', 'whm', 'webmail',
                'financial', 'confidential', 'salary', 'employee', 'hr',
                'bank', 'payment', 'invoice', 'transaction', 'credit'
            ],
            'sensitive_files': [
                '.env', 'config.json', 'config.php', 'settings.py', '.htaccess',
                '.htpasswd', 'web.config', 'robots.txt', 'sitemap.xml',
                'backup.zip', 'dump.sql', 'database.sql', 'backup.tar',
                'error.log', 'access.log', 'debug.log', 'wp-config.php',
            ],
            'sensitive_directories': [
                'admin', 'administrator', 'wp-admin', 'phpmyadmin', 'cpanel',
                'whm', 'webmail', 'portal', 'dashboard', 'control', 'manage',
                'api', 'rest', 'graphql', 'internal', 'private', 'secure',
                'auth', 'login', 'signin', 'config', 'backup', 'database',
                'sql', 'db', 'archive', 'old', 'temp', 'tmp', 'logs',
            ],
            'pakistani_phone_patterns': [
                r'\+92\s?3[0-9]{2}\s?[0-9]{7}',  # +92 3XX XXXXXXX
                r'03[0-9]{2}\-[0-9]{7}',         # 03XX-XXXXXXX
                r'03[0-9]{9}',                   # 03XXXXXXXXX
                r'\+92\s?[0-9]{2}\s?[0-9]{3}\s?[0-9]{4}',  # +92 XX XXX XXXX
            ],
            'critical_subdomains': [
                'admin', 'api', 'secure', 'portal', 'internal', 'dev', 'test',
                'staging', 'backup', 'db', 'database', 'mail', 'webmail',
                'cpanel', 'whm', 'ftp', 'ssh', 'vpn', 'remote'
            ],
            'sensitive_data_patterns': {
                'API_KEYS': r'[\'\"](?:api[_-]?key|apikey)[\'\"][^>]*?[\'\"]([A-Za-z0-9]{20,50})[\'\"]',
                'SECRET_KEYS': r'[\'\"](?:secret[_-]?key|private[_-]?key)[\'\"][^>]*?[\'\"]([A-Za-z0-9]{20,50})[\'\"]',
                'ACCESS_TOKENS': r'[\'\"](?:access[_-]?token|bearer[_-]?token)[\'\"][^>]*?[\'\"]([A-Za-z0-9]{20,100})[\'\"]',
                'DATABASE_URLS': r'[\'\"](?:database[_-]?url|db[_-]?url)[\'\"][^>]*?[\'\"]([A-Za-z0-9+/=]{20,100})[\'\"]',
            }
        }
    
    def setup_ultimate_logging(self):
        """Setup ultimate stealth logging"""
        log_dir = Path(f"yasir_intel_logs/{self.operation_name}")
        log_dir.mkdir(parents=True, exist_ok=True)
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - [YASIR_ULTIMATE] - %(message)s',
            handlers=[
                logging.FileHandler(log_dir / f"op_{self.session_id}.log"),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger("YASIR_ULTIMATE_INTEL")
    
    def setup_signal_handlers(self):
        """Setup signal handlers for clean exit"""
        def signal_handler(sig, frame):
            self.logger.info(f"Operation {self.operation_name} interrupted. Emergency cleanup...")
            self.emergency_cleanup()
            sys.exit(0)
        
        import signal
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
    
    def normalize_url(self, url: str) -> str:
        """Normalize and validate target URL"""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url.rstrip('/')
    
    def get_random_user_agent(self) -> str:
        """Get random user agent"""
        return random.choice(self.config['user_agents'])
    
    def get_stealth_delay(self) -> float:
        """Get random delay for maximum stealth"""
        return random.uniform(*self.config['delay_range'])
    
    def generate_stealth_headers(self) -> Dict:
        """Generate stealth headers to avoid detection"""
        headers = {
            'User-Agent': self.get_random_user_agent(),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        
        if self.config['stealth_mode']:
            headers.update({
                'DNT': '1',
                'Sec-GPC': '1',
                'Cache-Control': 'no-cache',
                'Pragma': 'no-cache'
            })
        
        return headers
    
    async def ultimate_request(self, url: str, session: aiohttp.ClientSession) -> Optional[Tuple[str, Dict, int]]:
        """Make ultimate HTTP request with maximum stealth and anonymity"""
        try:
            # Stealth delay
            await asyncio.sleep(self.get_stealth_delay())
            
            headers = self.generate_stealth_headers()
            
            async with session.get(
                url, 
                headers=headers, 
                timeout=aiohttp.ClientTimeout(total=self.config['timeout']),
                ssl=False,
                allow_redirects=True
            ) as response:
                content = await response.text()
                headers_dict = dict(response.headers)
                self.requests_made += 1
                return content, headers_dict, response.status
                
        except Exception as e:
            self.logger.debug(f"Stealth request failed for {url}: {e}")
            return None
    
    def extract_and_track_data(self, text: str, source_url: str):
        """Extract and track all types of intelligence with sources"""
        try:
            # Extract emails with sources
            emails = self.extract_high_value_emails(text)
            for email in emails:
                if email not in self.valid_emails:
                    self.valid_emails[email] = []
                if source_url not in self.valid_emails[email]:
                    self.valid_emails[email].append(source_url)
            
            # Extract phone numbers with sources
            phones = self.extract_pakistani_phones(text)
            for phone in phones:
                if phone not in self.valid_phone_numbers:
                    self.valid_phone_numbers[phone] = []
                if source_url not in self.valid_phone_numbers[phone]:
                    self.valid_phone_numbers[phone].append(source_url)
            
            # Extract social media with sources
            social = self.extract_high_value_social_media(text)
            for platform, profiles in social.items():
                for profile in profiles:
                    if profile not in self.social_media[platform]:
                        self.social_media[platform][profile] = []
                    if source_url not in self.social_media[platform][profile]:
                        self.social_media[platform][profile].append(source_url)
            
            # Extract sensitive data
            sensitive_data = self.extract_sensitive_data(text, source_url)
            self.exposed_data.extend(sensitive_data)
            
        except Exception as e:
            self.logger.error(f"Error in data extraction from {source_url}: {e}")
    
    def extract_high_value_emails(self, text: str) -> Set[str]:
        """Extract only valid organizational emails"""
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        potential_emails = set(re.findall(email_pattern, text, re.IGNORECASE))
        
        valid_emails = set()
        for email in potential_emails:
            email_lower = email.lower()
            # Filter out common false positives
            if any(invalid in email_lower for invalid in ['example.com', 'yourdomain.com', 'domain.com', 'email.com', 'noreply']):
                continue
            # Focus on organizational emails
            if any(domain in email_lower for domain in ['.edu.', '.ac.', '.gov.', '.org.', '.com', '.net']):
                valid_emails.add(email)
        
        return valid_emails
    
    def extract_pakistani_phones(self, text: str) -> Set[str]:
        """Extract only valid Pakistani phone numbers"""
        valid_phones = set()
        
        for pattern in self.patterns['pakistani_phone_patterns']:
            matches = re.findall(pattern, text)
            valid_phones.update(matches)
        
        return valid_phones
    
    def extract_sensitive_data(self, text: str, source_url: str) -> List[Dict]:
        """Extract sensitive data like API keys, tokens, etc."""
        exposed_data = []
        
        for data_type, pattern in self.patterns['sensitive_data_patterns'].items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                exposed_data.append({
                    'type': data_type,
                    'data': match[:50] + '...' if len(match) > 50 else match,
                    'source_url': source_url,
                    'severity': 'HIGH',
                    'confidence': 'MEDIUM',
                    'extraction_method': 'Pattern Matching',
                    'timestamp': datetime.now(timezone.utc).isoformat()
                })
                
                # Log sensitive finding
                self.logger.warning(f"🚨 SENSITIVE DATA FOUND: {data_type} at {source_url}")
        
        return exposed_data
    
    def extract_high_value_social_media(self, text: str) -> Dict[str, Set[str]]:
        """Extract organizational social media profiles"""
        social_patterns = {
            'linkedin': r'https?://(?:www\.)?linkedin\.com/(?:in|company)/[A-Za-z0-9_-]+',
            'twitter': r'https?://(?:www\.)?twitter\.com/[A-Za-z0-9_]+',
            'facebook': r'https?://(?:www\.)?facebook\.com/[A-Za-z0-9.]+',
            'instagram': r'https?://(?:www\.)?instagram\.com/[A-Za-z0-9._]+',
            'youtube': r'https?://(?:www\.)?youtube\.com/(?:user|channel)/[A-Za-z0-9_-]+'
        }
        
        found = defaultdict(set)
        for platform, pattern in social_patterns.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                # Filter out generic/share links
                if any(keyword in match.lower() for keyword in ['share', 'intent', 'widget', 'plugin']):
                    continue
                found[platform].add(match)
        
        return found
    
    def analyze_technologies_advanced(self, headers: Dict, content: str, url: str) -> Dict[str, Dict]:
        """Advanced technology analysis with risk assessment"""
        tech_signatures = {
            'WordPress': {
                'patterns': [r'wp-content', r'wp-includes', r'wordpress', r'/wp-json/'],
                'risk': 'MEDIUM',
            },
            'PHP': {
                'patterns': [r'\.php', r'X-Powered-By: PHP'],
                'risk': 'HIGH',
            },
            'Apache': {
                'patterns': [r'Server: Apache', r'Apache'],
                'risk': 'MEDIUM',
            },
            'Nginx': {
                'patterns': [r'Server: nginx', r'nginx'],
                'risk': 'LOW',
            },
            'React': {
                'patterns': [r'react', r'React', r'__NEXT_DATA__'],
                'risk': 'LOW',
            },
        }
        
        technologies = {}
        
        for tech, data in tech_signatures.items():
            detected = False
            
            for pattern in data['patterns']:
                if (re.search(pattern, str(headers), re.IGNORECASE) or 
                    re.search(pattern, content, re.IGNORECASE)):
                    detected = True
                    break
            
            if detected:
                technologies[tech] = {
                    'risk_level': data['risk'],
                    'confidence': 'HIGH',
                    'detected_in': url
                }
        
        return technologies
    
    def advanced_vulnerability_scan(self, headers: Dict, content: str, url: str) -> List[Dict]:
        """Advanced vulnerability assessment"""
        vulnerabilities = []
        
        # Security headers check
        security_headers = {
            'X-Frame-Options': 'Clickjacking protection',
            'X-Content-Type-Options': 'MIME sniffing protection',
            'Strict-Transport-Security': 'HSTS enforcement',
            'Content-Security-Policy': 'Content Security Policy',
            'X-XSS-Protection': 'XSS protection'
        }
        
        for header, description in security_headers.items():
            if header not in headers:
                vulnerabilities.append({
                    'type': 'MISSING_SECURITY_HEADER',
                    'severity': 'MEDIUM',
                    'description': f'Missing {header} - {description}',
                    'url': url,
                    'confidence': 'HIGH'
                })
        
        return vulnerabilities
    
    def perform_whois_analysis(self, domain: str) -> Dict:
        """Perform comprehensive WHOIS analysis"""
        try:
            whois_info = whois.whois(domain)
            
            # Convert to serializable format
            serializable_info = {}
            for key, value in whois_info.items():
                if isinstance(value, list):
                    serializable_info[key] = [str(item) for item in value]
                elif isinstance(value, datetime):
                    serializable_info[key] = value.isoformat()
                else:
                    serializable_info[key] = str(value) if value else None
            
            return {
                'domain': domain,
                'registration_date': serializable_info.get('creation_date'),
                'expiration_date': serializable_info.get('expiration_date'),
                'registrar': serializable_info.get('registrar'),
                'name_servers': serializable_info.get('name_servers', []),
                'emails': serializable_info.get('emails', []),
                'organization': serializable_info.get('org'),
                'country': serializable_info.get('country'),
            }
        except Exception as e:
            self.logger.error(f"WHOIS analysis failed: {e}")
            return {'error': str(e)}
    
    def perform_ssl_analysis(self, domain: str) -> Dict:
        """Perform comprehensive SSL certificate analysis"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
                    # Fix for datetime deprecation
                    not_after = cert['notAfter']
                    if isinstance(not_after, str):
                        cert_expiry = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                        validity_days = (cert_expiry - datetime.now(timezone.utc)).days
                    else:
                        validity_days = "Unknown"
                    
                    return {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'serialNumber': cert['serialNumber'],
                        'notBefore': cert['notBefore'],
                        'notAfter': cert['notAfter'],
                        'subjectAltName': cert.get('subjectAltName', []),
                        'cipher': cipher,
                        'tls_version': ssock.version(),
                        'validity_days': validity_days
                    }
        except Exception as e:
            self.logger.error(f"SSL analysis failed: {e}")
            return {'error': str(e)}
    
    def perform_network_analysis(self, domain: str) -> Dict:
        """Perform network infrastructure analysis"""
        try:
            # DNS resolution
            a_records = []
            mx_records = []
            ns_records = []
            
            try:
                a_records = [str(r) for r in dns.resolver.resolve(domain, 'A')]
            except: pass
            
            try:
                mx_records = [str(r) for r in dns.resolver.resolve(domain, 'MX')]
            except: pass
            
            try:
                ns_records = [str(r) for r in dns.resolver.resolve(domain, 'NS')]
            except: pass
            
            return {
                'a_records': a_records,
                'mx_records': mx_records,
                'ns_records': ns_records,
                'ip_addresses': a_records
            }
        except Exception as e:
            self.logger.error(f"Network analysis failed: {e}")
            return {'error': str(e)}
    
    async def focused_subdomain_enumeration(self, domain: str):
        """Focused subdomain enumeration on critical subdomains"""
        self.logger.info(f"Starting focused subdomain enumeration for {domain}")
        
        wordlist = self.patterns['critical_subdomains']
        
        async with aiohttp.ClientSession() as session:
            tasks = []
            for subdomain in wordlist:
                for protocol in ['https', 'http']:
                    test_url = f"{protocol}://{subdomain}.{domain}"
                    tasks.append(self.check_subdomain_focused(test_url, session))
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if result and isinstance(result, str):
                    if result not in self.critical_subdomains:
                        self.critical_subdomains[result] = []
                    self.critical_subdomains[result].append("Subdomain Enumeration")
    
    async def check_subdomain_focused(self, url: str, session: aiohttp.ClientSession) -> Optional[str]:
        """Check if subdomain exists"""
        try:
            async with session.head(
                url, 
                timeout=aiohttp.ClientTimeout(total=5),
                ssl=False,
                allow_redirects=True
            ) as response:
                if response.status < 400:
                    return url
        except:
            pass
        return None
    
    async def elite_directories_scan(self, base_url: str):
        """Scan for high-value directories"""
        self.logger.info(f"Scanning for high-value directories on {base_url}")
        
        wordlist = self.patterns['sensitive_directories']
        
        async with aiohttp.ClientSession() as session:
            tasks = []
            for directory in wordlist:
                test_url = f"{base_url}/{directory}"
                tasks.append(self.check_directory_elite(test_url, session))
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if result and isinstance(result, str):
                    if result not in self.admin_directories:
                        self.admin_directories[result] = []
                    self.admin_directories[result].append("Directory Scanning")
    
    async def check_directory_elite(self, url: str, session: aiohttp.ClientSession) -> Optional[str]:
        """Check if directory exists and is interesting"""
        try:
            async with session.get(
                url, 
                timeout=aiohttp.ClientTimeout(total=8),
                ssl=False,
                allow_redirects=True
            ) as response:
                if response.status < 400:
                    content = await response.text()
                    # Check if it's actually an admin/login page
                    if any(keyword in content.lower() for keyword in ['login', 'admin', 'password', 'username', 'dashboard']):
                        return url
        except:
            pass
        return None
    
    async def elite_crawling(self):
        """Elite focused crawling for high-value intelligence"""
        self.logger.info(f"Starting elite focused crawling for {self.target_url}")
        
        async with aiohttp.ClientSession() as session:
            while self.url_queue and len(self.scraped_urls) < self.config['max_urls']:
                current_batch = []
                while self.url_queue and len(current_batch) < self.config['concurrent_requests']:
                    url = self.url_queue.popleft()
                    if url not in self.scraped_urls:
                        current_batch.append(url)
                
                tasks = [self.process_elite_url(url, session) for url in current_batch]
                await asyncio.gather(*tasks)
                
                # Progress reporting
                self.logger.info(f"Yasir Ultimate Progress: {self.requests_made} requests, {len(self.scraped_urls)} URLs, {len(self.valid_emails)} emails, {len(self.valid_phone_numbers)} phones")
    
    async def process_elite_url(self, url: str, session: aiohttp.ClientSession):
        """Process URL with elite intelligence gathering"""
        if url in self.scraped_urls:
            return
        
        self.scraped_urls.add(url)
        
        result = await self.ultimate_request(url, session)
        if not result:
            return
        
        content, headers, status_code = result
        
        # Extract and track all intelligence
        self.extract_and_track_data(content, url)
        
        # Advanced analysis
        tech_analysis = self.analyze_technologies_advanced(headers, content, url)
        self.technologies.update(tech_analysis)
        
        vulns = self.advanced_vulnerability_scan(headers, content, url)
        self.vulnerabilities.extend(vulns)
        
        # Extract new URLs
        new_urls = self.extract_focused_urls(content, url)
        for new_url in new_urls:
            if (new_url not in self.scraped_urls and 
                new_url not in self.url_queue and
                self.is_relevant_url(new_url)):
                self.url_queue.append(new_url)
    
    def extract_focused_urls(self, content: str, base_url: str) -> Set[str]:
        """Extract only high-value URLs"""
        urls = set()
        soup = BeautifulSoup(content, 'html.parser')
        
        for link in soup.find_all('a', href=True):
            href = link['href']
            absolute_url = urllib.parse.urljoin(base_url, href)
            
            # Only add relevant URLs
            if self.is_relevant_url(absolute_url):
                urls.add(absolute_url)
        
        return urls
    
    def is_relevant_url(self, url: str) -> bool:
        """Check if URL is relevant to target"""
        target_domain = urllib.parse.urlparse(self.target_url).netloc
        url_domain = urllib.parse.urlparse(url).netloc
        
        irrelevant_domains = {
            'facebook.com', 'twitter.com', 'linkedin.com', 'instagram.com',
            'youtube.com', 'google.com', 'addthis.com', 'sharethis.com'
        }
        
        if url_domain in irrelevant_domains:
            return False
        
        return target_domain in url_domain or url_domain.endswith(target_domain)
    
    def generate_individual_excel_reports(self):
        """Generate individual Excel files for each intelligence category"""
        base_dir = Path(f"yasir_intel_reports/{self.operation_name}")
        base_dir.mkdir(parents=True, exist_ok=True)
        
        try:
            # 1. Emails Report
            if self.valid_emails:
                emails_df = pd.DataFrame([
                    {'Email': email, 'Source_URLs': ', '.join(sources), 'Found_Count': len(sources)}
                    for email, sources in self.valid_emails.items()
                ])
                emails_df.to_excel(base_dir / "01_Emails_Intelligence.xlsx", index=False)
            
            # 2. Phone Numbers Report
            if self.valid_phone_numbers:
                phones_df = pd.DataFrame([
                    {'Phone_Number': phone, 'Source_URLs': ', '.join(sources), 'Found_Count': len(sources)}
                    for phone, sources in self.valid_phone_numbers.items()
                ])
                phones_df.to_excel(base_dir / "02_Phone_Numbers_Intelligence.xlsx", index=False)
            
            # 3. Social Media Report
            if self.social_media:
                social_data = []
                for platform, profiles in self.social_media.items():
                    for profile, sources in profiles.items():
                        social_data.append({
                            'Platform': platform,
                            'Profile_URL': profile,
                            'Source_URLs': ', '.join(sources),
                            'Found_Count': len(sources)
                        })
                if social_data:
                    social_df = pd.DataFrame(social_data)
                    social_df.to_excel(base_dir / "03_Social_Media_Intelligence.xlsx", index=False)
            
            # 4. Vulnerabilities Report
            if self.vulnerabilities:
                vuln_df = pd.DataFrame(self.vulnerabilities)
                vuln_df.to_excel(base_dir / "04_Vulnerabilities_Found.xlsx", index=False)
            
            # 5. Technologies Report
            if self.technologies:
                tech_data = []
                for tech, info in self.technologies.items():
                    tech_data.append({
                        'Technology': tech,
                        'Risk_Level': info['risk_level'],
                        'Confidence': info['confidence'],
                        'Detected_In': info.get('detected_in', 'N/A')
                    })
                tech_df = pd.DataFrame(tech_data)
                tech_df.to_excel(base_dir / "05_Technologies_Identified.xlsx", index=False)
            
            # 6. Exposed Data Report
            if self.exposed_data:
                exposed_df = pd.DataFrame(self.exposed_data)
                exposed_df.to_excel(base_dir / "06_Sensitive_Data_Exposed.xlsx", index=False)
            
            # 7. Infrastructure Report
            infra_data = {
                'WHOIS_Info': [str(self.whois_data)],
                'SSL_Analysis': [str(self.ssl_data)],
                'Network_Info': [str(self.network_info)]
            }
            infra_df = pd.DataFrame(infra_data)
            infra_df.to_excel(base_dir / "07_Infrastructure_Analysis.xlsx", index=False)
            
            # 8. Subdomains Report
            if self.critical_subdomains:
                subdomains_df = pd.DataFrame([
                    {'Subdomain': sub, 'Source': ', '.join(sources)}
                    for sub, sources in self.critical_subdomains.items()
                ])
                subdomains_df.to_excel(base_dir / "08_Critical_Subdomains.xlsx", index=False)
            
            # 9. Directories Report
            if self.admin_directories:
                directories_df = pd.DataFrame([
                    {'Directory': dir, 'Source': ', '.join(sources)}
                    for dir, sources in self.admin_directories.items()
                ])
                directories_df.to_excel(base_dir / "09_Admin_Directories.xlsx", index=False)
            
            # 10. Master Summary Report
            summary_data = {
                'Category': [
                    'High-Value Emails', 'Valid Phone Numbers', 'Social Media Profiles',
                    'Vulnerabilities Found', 'Technologies Identified', 'Sensitive Data Exposed',
                    'Critical Subdomains', 'Admin Directories', 'Total Requests', 'URLs Analyzed'
                ],
                'Count': [
                    len(self.valid_emails), len(self.valid_phone_numbers),
                    sum(len(profiles) for profiles in self.social_media.values()),
                    len(self.vulnerabilities), len(self.technologies), len(self.exposed_data),
                    len(self.critical_subdomains), len(self.admin_directories),
                    self.requests_made, len(self.scraped_urls)
                ]
            }
            summary_df = pd.DataFrame(summary_data)
            summary_df.to_excel(base_dir / "10_Master_Summary.xlsx", index=False)
            
            self.logger.info(f"Individual Excel reports generated in: {base_dir}")
            
        except Exception as e:
            self.logger.error(f"Error generating Excel reports: {e}")
            self.logger.error(traceback.format_exc())
    
    def generate_detailed_findings_report(self):
        """Generate detailed findings report with extraction methods"""
        base_dir = Path(f"yasir_intel_reports/{self.operation_name}")
        
        findings = []
        
        # Email findings
        for email, sources in self.valid_emails.items():
            findings.append({
                'Type': 'Email',
                'Data': email,
                'Source_URLs': ', '.join(sources[:3]),  # First 3 sources
                'Extraction_Method': 'Pattern Matching + Domain Validation',
                'Confidence': 'High',
                'Risk_Level': 'Medium'
            })
        
        # Phone findings
        for phone, sources in self.valid_phone_numbers.items():
            findings.append({
                'Type': 'Phone Number',
                'Data': phone,
                'Source_URLs': ', '.join(sources[:3]),
                'Extraction_Method': 'Pakistani Phone Pattern Matching',
                'Confidence': 'High', 
                'Risk_Level': 'Low'
            })
        
        # Sensitive data findings
        for exposed in self.exposed_data:
            findings.append({
                'Type': exposed['type'],
                'Data': exposed['data'],
                'Source_URLs': exposed['source_url'],
                'Extraction_Method': exposed.get('extraction_method', 'Pattern Matching'),
                'Confidence': exposed.get('confidence', 'Medium'),
                'Risk_Level': exposed.get('severity', 'High')
            })
        
        if findings:
            findings_df = pd.DataFrame(findings)
            findings_df.to_excel(base_dir / "11_Detailed_Findings_Analysis.xlsx", index=False)
            self.logger.info("Detailed findings report generated")
    
    def save_yasir_operation_data(self):
        """Save Yasir ultimate operation data"""
        try:
            operation_dir = Path(f"yasir_intel_reports/{self.operation_name}")
            operation_dir.mkdir(parents=True, exist_ok=True)
            
            # Generate individual Excel reports
            self.generate_individual_excel_reports()
            self.generate_detailed_findings_report()
            
            # Save JSON report
            report = self.generate_yasir_ultimate_report()
            json_file = operation_dir / f"Yasir_Ultimate_Intelligence_{self.session_id}.json"
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"Yasir ultimate operation data saved to {operation_dir}")
            
        except Exception as e:
            self.logger.error(f"Error saving operation data: {e}")
            self.logger.error(traceback.format_exc())
    
    def generate_yasir_ultimate_report(self) -> Dict:
        """Generate Yasir Abbas ultimate intelligence report"""
        current_time = datetime.now(timezone.utc).isoformat()
        
        report = {
            'operation_metadata': {
                'operation_name': self.operation_name,
                'operator': self.operator_name,
                'session_id': self.session_id,
                'timestamp': current_time,
                'target': self.target_url,
                'notice': self.usage_notice
            },
            'executive_summary': {
                'high_value_emails': len(self.valid_emails),
                'valid_phone_numbers': len(self.valid_phone_numbers),
                'social_media_profiles': sum(len(profiles) for profiles in self.social_media.values()),
                'vulnerabilities_found': len(self.vulnerabilities),
                'technologies_identified': len(self.technologies),
                'exposed_data_found': len(self.exposed_data),
                'critical_subdomains': len(self.critical_subdomains),
                'admin_directories': len(self.admin_directories)
            },
            'operational_metrics': {
                'total_requests': self.requests_made,
                'urls_analyzed': len(self.scraped_urls),
                'scan_duration': getattr(self, 'scan_duration', 0),
                'efficiency_score': self.calculate_efficiency_score(),
            }
        }
        
        return report
    
    def calculate_efficiency_score(self) -> float:
        """Calculate operational efficiency score"""
        if not hasattr(self, 'scan_duration') or self.scan_duration == 0:
            return 0.0
        
        intelligence_items = (
            len(self.valid_emails) + len(self.valid_phone_numbers) + 
            len(self.vulnerabilities) + len(self.exposed_data)
        )
        efficiency = intelligence_items / self.scan_duration
        return round(efficiency, 2)
    
    def emergency_cleanup(self):
        """Emergency data cleanup"""
        self.logger.warning("Performing emergency cleanup...")
        try:
            self.save_yasir_operation_data()
        except Exception as e:
            self.logger.error(f"Emergency cleanup failed: {e}")
    
    async def execute_yasir_ultimate_reconnaissance(self):
        """Execute Yasir ultimate reconnaissance operation"""
        self.start_time = datetime.now(timezone.utc).isoformat()
        self.logger.info(f"Starting YASIR ULTIMATE reconnaissance: {self.operation_name}")
        
        try:
            domain = urllib.parse.urlparse(self.target_url).netloc
            
            # Phase 1: Infrastructure Analysis
            self.logger.info("Phase 1: Infrastructure Analysis")
            self.whois_data = await asyncio.get_event_loop().run_in_executor(None, self.perform_whois_analysis, domain)
            self.ssl_data = await asyncio.get_event_loop().run_in_executor(None, self.perform_ssl_analysis, domain)
            self.network_info = await asyncio.get_event_loop().run_in_executor(None, self.perform_network_analysis, domain)
            
            # Phase 2: Critical Infrastructure Discovery
            self.logger.info("Phase 2: Critical Infrastructure Discovery")
            await self.focused_subdomain_enumeration(domain)
            await self.elite_directories_scan(self.target_url)
            
            # Add critical infrastructure to queue
            for subdomain in self.critical_subdomains:
                self.url_queue.append(subdomain)
            
            for directory in self.admin_directories:
                self.url_queue.append(directory)
            
            # Phase 3: Elite Focused Crawling
            self.logger.info("Phase 3: Elite Focused Crawling")
            await self.elite_crawling()
            
            self.end_time = datetime.now(timezone.utc).isoformat()
            self.scan_duration = (datetime.fromisoformat(self.end_time) - 
                                 datetime.fromisoformat(self.start_time)).total_seconds()
            
            # Save results
            self.save_yasir_operation_data()
            
            self.logger.info(f"YASIR ULTIMATE reconnaissance completed in {self.scan_duration:.2f} seconds")
            self.logger.info(f"🎯 Intelligence Summary:")
            self.logger.info(f"   📧 Emails: {len(self.valid_emails)}")
            self.logger.info(f"   📞 Phone Numbers: {len(self.valid_phone_numbers)}")
            self.logger.info(f"   🌐 Social Media: {sum(len(profiles) for profiles in self.social_media.values())}")
            self.logger.info(f"   ⚠️  Vulnerabilities: {len(self.vulnerabilities)}")
            self.logger.info(f"   🔧 Technologies: {len(self.technologies)}")
            self.logger.info(f"   🔓 Sensitive Data: {len(self.exposed_data)}")
            self.logger.info(f"   🌐 Subdomains: {len(self.critical_subdomains)}")
            self.logger.info(f"   📁 Directories: {len(self.admin_directories)}")
            
        except Exception as e:
            self.logger.error(f"Reconnaissance failed: {e}")
            self.logger.error(traceback.format_exc())
            self.emergency_cleanup()
            raise

class YasirCommandCenter:
    """Yasir Command Center for managing ultimate operations"""
    
    def __init__(self):
        self.operations: Dict[str, YasirUltimateReconSystem] = {}
    
    def create_operation(self, target: str, operation_name: str) -> str:
        """Create new Yasir ultimate operation"""
        operation = YasirUltimateReconSystem(target, operation_name)
        self.operations[operation_name] = operation
        return operation_name
    
    async def execute_operation(self, operation_name: str):
        """Execute Yasir ultimate operation"""
        if operation_name not in self.operations:
            raise ValueError(f"Operation {operation_name} not found")
        
        await self.operations[operation_name].execute_yasir_ultimate_reconnaissance()
    
    def get_operation_report(self, operation_name: str) -> Dict:
        """Get Yasir ultimate operation report"""
        if operation_name not in self.operations:
            raise ValueError(f"Operation {operation_name} not found")
        
        return self.operations[operation_name].generate_yasir_ultimate_report()

def display_yasir_banner():
    """Display Yasir Abbas ultimate banner"""
    banner = """
    ╔══════════════════════════════════════════════════════════════════════════════╗
    ║                  YASIR ABBAS - ULTIMATE INTELLIGENCE SYSTEM                 ║
    ║                         GOVERNMENT RED TEAM RECONNAISSANCE                  ║
    ║                              ULTIMATE LORD LEVEL v6.0                       ║
    ║                                                                              ║
    ║           Complete Stealth & Anonymity | Maximum Efficiency | Elite Results ║
    ║                      FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY            ║
    ╚══════════════════════════════════════════════════════════════════════════════╝
    """
    print(banner)

def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(description="YASIR ABBAS - ULTIMATE INTELLIGENCE SYSTEM")
    parser.add_argument("target", help="Target URL or domain")
    parser.add_argument("-o", "--operation", help="Operation name", default=f"YASIR_OP_{int(time.time())}")
    parser.add_argument("--stealth", action="store_true", help="Enable maximum stealth mode")
    
    args = parser.parse_args()
    
    display_yasir_banner()
    
    print(f"""
    🎯 Target: {args.target}
    🔧 Operation: {args.operation}
    🕵️  Operator: Yasir Abbas
    🛡️  Mode: ULTIMATE STEALTH
    ⚠️  Notice: FOR EDUCATIONAL PURPOSES ONLY
    """)
    
    # Create Yasir command center
    command_center = YasirCommandCenter()
    operation_name = command_center.create_operation(args.target, args.operation)
    
    # Execute operation
    try:
        asyncio.run(command_center.execute_operation(operation_name))
        
        # Display Yasir ultimate results
        report = command_center.get_operation_report(operation_name)
        print("\n" + "="*120)
        print("YASIR ABBAS - ULTIMATE INTELLIGENCE REPORT")
        print("="*120)
        
        summary = report['executive_summary']
        print(f"\n🎯 EXECUTIVE SUMMARY:")
        print(f"  📧 High-Value Emails: {summary['high_value_emails']}")
        print(f"  📞 Valid Phone Numbers: {summary['valid_phone_numbers']}")
        print(f"  🌐 Social Media Profiles: {summary['social_media_profiles']}")
        print(f"  ⚠️  Vulnerabilities Found: {summary['vulnerabilities_found']}")
        print(f"  🔧 Technologies Identified: {summary['technologies_identified']}")
        print(f"  🔓 Exposed Data Found: {summary['exposed_data_found']}")
        print(f"  🌐 Critical Subdomains: {summary['critical_subdomains']}")
        print(f"  📁 Admin Directories: {summary['admin_directories']}")
        
        metrics = report['operational_metrics']
        print(f"\n📊 OPERATIONAL METRICS:")
        print(f"  🔄 Requests Made: {metrics['total_requests']}")
        print(f"  🌐 URLs Analyzed: {metrics['urls_analyzed']}")
        print(f"  ⏱️  Scan Duration: {metrics['scan_duration']:.2f} seconds")
        print(f"  📈 Efficiency Score: {metrics['efficiency_score']}")
        
        print(f"\n💡 INDIVIDUAL REPORTS GENERATED:")
        print(f"  📁 Location: yasir_intel_reports/{operation_name}/")
        print(f"  📊 11 Detailed Excel Files with Complete Intelligence")
        print(f"  🔍 Source Tracking for Every Finding")
        print(f"  🚨 Sensitive Data Analysis")
        print(f"  📈 Extraction Methods Documented")
        
    except KeyboardInterrupt:
        print("\n[!] Operation interrupted by user - Data preserved")
    except Exception as e:
        print(f"\n[!] Operation failed: {e}")

if __name__ == "__main__":
    main()
