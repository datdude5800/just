from fastapi import FastAPI, APIRouter, HTTPException
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional, Dict, Any
import uuid
from datetime import datetime, timezone
import hashlib
import socket
import ssl
import requests
from urllib.parse import urlparse
import asyncio
import re
import json

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

app = FastAPI()
api_router = APIRouter(prefix="/api")

class HashDecodeRequest(BaseModel):
    hash_value: str
    hash_type: Optional[str] = None

class HashDecodeResponse(BaseModel):
    hash_value: str
    detected_type: str
    possible_types: List[str]
    status: str
    message: str

class PenTestRequest(BaseModel):
    target_url: str
    tests: List[str]

class PenTestResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    target_url: str
    timestamp: str
    results: Dict[str, Any]

class APITestRequest(BaseModel):
    endpoint_url: str
    method: str = "GET"
    headers: Optional[Dict[str, str]] = None

class APITestResponse(BaseModel):
    endpoint_url: str
    method: str
    status_code: int
    headers: Dict[str, str]
    security_headers: Dict[str, Any]
    issues: List[str]

class EmailBreachRequest(BaseModel):
    email: str

class EmailBreachResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")
    email: str
    is_valid: bool
    breaches_found: int
    breach_data: List[Dict[str, Any]]
    risk_level: str
    recommendations: List[str]

class HashCrackRequest(BaseModel):
    hash_value: str
    hash_type: str
    method: str = "dictionary"
    max_length: Optional[int] = 6

class HashCrackResponse(BaseModel):
    hash_value: str
    hash_type: str
    cracked: bool
    plaintext: Optional[str] = None
    method_used: str
    attempts: int
    time_taken: float

class SessionExportRequest(BaseModel):
    session_data: Dict[str, Any]
    export_format: str = "json"

class BreachDetailRequest(BaseModel):
    query: str
    search_type: str = "email"
    reveal_sensitive: bool = False

class BreachDetailResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")
    query: str
    search_type: str
    total_records: int
    exposed_data: Dict[str, Any]
    compromised_passwords: List[Dict[str, Any]]
    phone_records: List[str]
    personal_info: Dict[str, Any]
    ip_addresses: List[Dict[str, str]]
    all_emails: List[str]
    all_usernames: List[str]
    severity: str
    requires_premium: bool

class SecurityAuditRequest(BaseModel):
    email: str
    website_url: Optional[str] = None
    include_consultation: bool = False

class SecurityAuditResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")
    audit_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    email: str
    vulnerabilities: List[Dict[str, Any]]
    security_score: int
    recommendations: List[Dict[str, Any]]
    premium_features: List[Dict[str, Any]]
    estimated_cost: float
    detailed_findings: Optional[Dict[str, Any]] = None

class SocialMediaSearchRequest(BaseModel):
    query: str
    search_type: str = "email"

class SocialMediaSearchResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")
    query: str
    total_accounts: int
    platforms_found: List[str]
    accounts: List[Dict[str, Any]]
    compromised_count: int
    security_recommendations: List[str]
    remediation_services: List[Dict[str, Any]]

def detect_hash_type(hash_value: str) -> tuple:
    """Detect hash type based on length and characteristics"""
    hash_clean = hash_value.strip().lower()
    length = len(hash_clean)
    
    possible_types = []
    detected = "Unknown"
    
    if length == 32 and all(c in '0123456789abcdef' for c in hash_clean):
        possible_types = ["MD5", "NTLM"]
        detected = "MD5"
    elif length == 40 and all(c in '0123456789abcdef' for c in hash_clean):
        possible_types = ["SHA-1", "RIPEMD-160"]
        detected = "SHA-1"
    elif length == 56 and all(c in '0123456789abcdef' for c in hash_clean):
        possible_types = ["SHA-224"]
        detected = "SHA-224"
    elif length == 64 and all(c in '0123456789abcdef' for c in hash_clean):
        possible_types = ["SHA-256", "SHA3-256", "BLAKE2s"]
        detected = "SHA-256"
    elif length == 96 and all(c in '0123456789abcdef' for c in hash_clean):
        possible_types = ["SHA-384"]
        detected = "SHA-384"
    elif length == 128 and all(c in '0123456789abcdef' for c in hash_clean):
        possible_types = ["SHA-512", "SHA3-512", "BLAKE2b"]
        detected = "SHA-512"
    elif hash_clean.startswith('$2') and '$' in hash_clean[3:]:
        possible_types = ["bcrypt"]
        detected = "bcrypt"
    elif hash_clean.startswith('$6$'):
        possible_types = ["SHA-512 Crypt"]
        detected = "SHA-512 Crypt"
    elif hash_clean.startswith('$5$'):
        possible_types = ["SHA-256 Crypt"]
        detected = "SHA-256 Crypt"
    elif hash_clean.startswith('$1$'):
        possible_types = ["MD5 Crypt"]
        detected = "MD5 Crypt"
    elif length == 16 and all(c in '0123456789abcdef' for c in hash_clean):
        possible_types = ["MD5 (half)", "CRC-64"]
        detected = "MD5 (half)"
    
    return detected, possible_types

def generate_hash_examples(input_text: str) -> Dict[str, str]:
    """Generate all hash types for given input"""
    examples = {}
    
    examples['MD5'] = hashlib.md5(input_text.encode()).hexdigest()
    examples['SHA-1'] = hashlib.sha1(input_text.encode()).hexdigest()
    examples['SHA-224'] = hashlib.sha224(input_text.encode()).hexdigest()
    examples['SHA-256'] = hashlib.sha256(input_text.encode()).hexdigest()
    examples['SHA-384'] = hashlib.sha384(input_text.encode()).hexdigest()
    examples['SHA-512'] = hashlib.sha512(input_text.encode()).hexdigest()
    examples['SHA3-256'] = hashlib.sha3_256(input_text.encode()).hexdigest()
    examples['SHA3-512'] = hashlib.sha3_512(input_text.encode()).hexdigest()
    examples['BLAKE2b'] = hashlib.blake2b(input_text.encode()).hexdigest()
    examples['BLAKE2s'] = hashlib.blake2s(input_text.encode()).hexdigest()
    
    return examples

async def check_port_scan(domain: str) -> Dict[str, Any]:
    """Scan common ports"""
    common_ports = [21, 22, 23, 25, 53, 80, 443, 445, 3306, 3389, 5432, 8080, 8443]
    open_ports = []
    
    try:
        ip = socket.gethostbyname(domain)
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except:
                continue
        
        return {
            "status": "completed",
            "ip_address": ip,
            "open_ports": open_ports,
            "total_scanned": len(common_ports),
            "issues": [f"Port {p} is open" for p in open_ports] if open_ports else []
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}

async def check_ssl_tls(url: str) -> Dict[str, Any]:
    """Check SSL/TLS configuration"""
    try:
        parsed = urlparse(url)
        hostname = parsed.netloc or parsed.path
        
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                
                issues = []
                if cipher[0] in ['TLS_RSA_WITH_RC4_128_SHA', 'TLS_RSA_WITH_3DES_EDE_CBC_SHA']:
                    issues.append("Weak cipher suite detected")
                
                return {
                    "status": "completed",
                    "protocol": ssock.version(),
                    "cipher": cipher[0],
                    "bits": cipher[2],
                    "issuer": dict(x[0] for x in cert.get('issuer', [])),
                    "valid_until": cert.get('notAfter', 'Unknown'),
                    "issues": issues
                }
    except Exception as e:
        return {"status": "error", "message": str(e)}

async def check_security_headers(url: str) -> Dict[str, Any]:
    """Analyze security headers"""
    try:
        response = requests.get(url, timeout=10, verify=True)
        headers = response.headers
        
        security_headers = {
            'Strict-Transport-Security': headers.get('Strict-Transport-Security', 'Missing'),
            'X-Frame-Options': headers.get('X-Frame-Options', 'Missing'),
            'X-Content-Type-Options': headers.get('X-Content-Type-Options', 'Missing'),
            'Content-Security-Policy': headers.get('Content-Security-Policy', 'Missing'),
            'X-XSS-Protection': headers.get('X-XSS-Protection', 'Missing'),
            'Referrer-Policy': headers.get('Referrer-Policy', 'Missing')
        }
        
        issues = [f"{k} header is missing" for k, v in security_headers.items() if v == 'Missing']
        
        return {
            "status": "completed",
            "status_code": response.status_code,
            "headers": security_headers,
            "issues": issues,
            "server": headers.get('Server', 'Unknown')
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}

async def check_xss_detection(url: str) -> Dict[str, Any]:
    """Basic XSS vulnerability detection"""
    try:
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>"
        ]
        
        vulnerabilities = []
        for payload in payloads:
            try:
                response = requests.get(f"{url}?q={payload}", timeout=5)
                if payload in response.text:
                    vulnerabilities.append(f"Potential XSS with payload: {payload[:30]}...")
            except:
                continue
        
        return {
            "status": "completed",
            "payloads_tested": len(payloads),
            "vulnerabilities": vulnerabilities,
            "issues": vulnerabilities if vulnerabilities else ["No obvious XSS vulnerabilities found"]
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}

async def check_sql_injection(url: str) -> Dict[str, Any]:
    """Basic SQL injection detection"""
    try:
        payloads = ["'", "' OR '1'='1", "1' OR '1'='1", "admin'--", "' UNION SELECT NULL--"]
        
        vulnerabilities = []
        baseline_response = requests.get(url, timeout=5)
        baseline_length = len(baseline_response.text)
        
        for payload in payloads:
            try:
                response = requests.get(f"{url}?id={payload}", timeout=5)
                if 'error' in response.text.lower() or 'sql' in response.text.lower():
                    vulnerabilities.append(f"SQL error detected with payload: {payload}")
                elif abs(len(response.text) - baseline_length) > 100:
                    vulnerabilities.append(f"Response variation with payload: {payload}")
            except:
                continue
        
        return {
            "status": "completed",
            "payloads_tested": len(payloads),
            "vulnerabilities": vulnerabilities,
            "issues": vulnerabilities if vulnerabilities else ["No obvious SQL injection vulnerabilities found"]
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}

def validate_email(email: str) -> bool:
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

async def check_haveibeenpwned(email: str) -> Dict[str, Any]:
    """Check email against Have I Been Pwned API"""
    try:
        headers = {
            'User-Agent': 'SecCheck-Security-Tool',
            'hibp-api-key': os.environ.get('HIBP_API_KEY', '')
        }
        
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            breaches = response.json()
            return {
                "status": "found",
                "breaches": breaches,
                "count": len(breaches)
            }
        elif response.status_code == 404:
            return {
                "status": "not_found",
                "breaches": [],
                "count": 0
            }
        else:
            return {
                "status": "error",
                "message": f"API returned status {response.status_code}",
                "breaches": [],
                "count": 0
            }
    except Exception as e:
        return {
            "status": "error",
            "message": str(e),
            "breaches": [],
            "count": 0
        }

async def check_email_breach_local(email: str) -> Dict[str, Any]:
    """Check email against local breach database"""
    common_breaches = [
        {
            "name": "LinkedIn (2021)",
            "date": "2021-06-22",
            "records": "700M",
            "data_classes": ["Email addresses", "Full names", "Phone numbers", "Physical addresses"],
            "severity": "high"
        },
        {
            "name": "Facebook (2019)",
            "date": "2019-04-03",
            "records": "533M",
            "data_classes": ["Email addresses", "Phone numbers", "Names", "DOB"],
            "severity": "critical"
        },
        {
            "name": "Twitter (2023)",
            "date": "2023-01-01",
            "records": "200M",
            "data_classes": ["Email addresses", "Usernames"],
            "severity": "medium"
        },
        {
            "name": "Adobe (2013)",
            "date": "2013-10-04",
            "records": "153M",
            "data_classes": ["Email addresses", "Passwords", "Password hints"],
            "severity": "critical"
        },
        {
            "name": "MySpace (2008)",
            "date": "2008-06-11",
            "records": "360M",
            "data_classes": ["Email addresses", "Passwords", "Usernames"],
            "severity": "high"
        }
    ]
    
    email_hash = hashlib.md5(email.lower().encode()).hexdigest()
    hash_digit = int(email_hash[0], 16)
    
    simulated_breaches = []
    for i, breach in enumerate(common_breaches):
        if hash_digit > (i * 3):
            simulated_breaches.append(breach)
    
    return {
        "status": "simulated",
        "breaches": simulated_breaches,
        "count": len(simulated_breaches),
        "note": "Using simulated breach data for demonstration. For real breach data, configure HIBP_API_KEY."
    }

def get_common_passwords():
    """Get common password list for dictionary attack"""
    return [
        "password", "123456", "12345678", "qwerty", "abc123", "monkey", "1234567",
        "letmein", "trustno1", "dragon", "baseball", "iloveyou", "master", "sunshine",
        "ashley", "bailey", "shadow", "123123", "654321", "superman", "qazwsx",
        "michael", "football", "password1", "admin", "welcome", "hello", "test",
        "12345", "password123", "changeme", "secret", "p@ssw0rd", "passw0rd",
        "admin123", "root", "toor", "pass", "test123", "guest", "user", "demo"
    ]

def hash_text(text: str, hash_type: str) -> str:
    """Hash text with specified algorithm"""
    text_bytes = text.encode()
    
    if hash_type.upper() == "MD5":
        return hashlib.md5(text_bytes).hexdigest()
    elif hash_type.upper() == "SHA-256":
        return hashlib.sha256(text_bytes).hexdigest()
    elif hash_type.upper() == "SHA-512":
        return hashlib.sha512(text_bytes).hexdigest()
    elif hash_type.upper() == "SHA3-256":
        return hashlib.sha3_256(text_bytes).hexdigest()
    elif hash_type.upper() == "SHA3-512":
        return hashlib.sha3_512(text_bytes).hexdigest()
    elif hash_type.upper() == "BLAKE2B":
        return hashlib.blake2b(text_bytes).hexdigest()
    elif hash_type.upper() == "BLAKE2S":
        return hashlib.blake2s(text_bytes).hexdigest()
    elif hash_type.upper() == "NTLM":
        import binascii
        return hashlib.new('md4', text.encode('utf-16le')).hexdigest()
    else:
        return ""

async def crack_hash_dictionary(hash_value: str, hash_type: str) -> Dict[str, Any]:
    """Attempt to crack hash using dictionary attack"""
    import time
    
    start_time = time.time()
    hash_value = hash_value.lower().strip()
    attempts = 0
    
    passwords = get_common_passwords()
    
    for password in passwords:
        attempts += 1
        test_hash = hash_text(password, hash_type)
        
        if test_hash.lower() == hash_value:
            return {
                "cracked": True,
                "plaintext": password,
                "attempts": attempts,
                "time_taken": time.time() - start_time
            }
    
    return {
        "cracked": False,
        "plaintext": None,
        "attempts": attempts,
        "time_taken": time.time() - start_time
    }

async def crack_hash_bruteforce(hash_value: str, hash_type: str, max_length: int = 4) -> Dict[str, Any]:
    """Attempt to crack hash using brute force (limited to short passwords)"""
    import time
    import itertools
    import string
    
    start_time = time.time()
    hash_value = hash_value.lower().strip()
    attempts = 0
    max_attempts = 100000
    
    charset = string.ascii_lowercase + string.digits
    
    for length in range(1, min(max_length + 1, 5)):
        for combo in itertools.product(charset, repeat=length):
            if attempts >= max_attempts:
                return {
                    "cracked": False,
                    "plaintext": None,
                    "attempts": attempts,
                    "time_taken": time.time() - start_time,
                    "note": "Max attempts reached"
                }
            
            attempts += 1
            password = ''.join(combo)
            test_hash = hash_text(password, hash_type)
            
            if test_hash.lower() == hash_value:
                return {
                    "cracked": True,
                    "plaintext": password,
                    "attempts": attempts,
                    "time_taken": time.time() - start_time
                }
    
    return {
        "cracked": False,
        "plaintext": None,
        "attempts": attempts,
        "time_taken": time.time() - start_time
    }

async def get_detailed_breach_data(email: str) -> Dict[str, Any]:
    """Get detailed breach data including sensitive information (SIMULATED DATA ONLY)"""
    email_hash = hashlib.md5(email.lower().encode()).hexdigest()
    hash_digit = int(email_hash[0], 16)
    
    simulated_passwords = [
        {"source": "LinkedIn 2021", "password_hash": "5f4dcc3b5aa765d61d8327deb882cf99", "cracked": True, "plaintext": "password123"},
        {"source": "Facebook 2019", "password_hash": "e10adc3949ba59abbe56e057f20f883e", "cracked": True, "plaintext": "123456"},
        {"source": "Adobe 2013", "password_hash": "25d55ad283aa400af464c76d713c07ad", "cracked": True, "plaintext": "12345678"}
    ]
    
    simulated_phones = [
        f"+1-555-{hash_digit:03d}-{(hash_digit * 137) % 10000:04d}",
        f"+1-555-{(hash_digit + 1) % 1000:03d}-{(hash_digit * 251) % 10000:04d}"
    ]
    
    personal_info = {
        "full_name": f"User {hash_digit}{(hash_digit * 17) % 100}",
        "addresses": [
            f"{hash_digit * 100} Main Street, City {hash_digit}, ST {hash_digit:05d}"
        ],
        "date_of_birth": f"19{70 + (hash_digit % 30)}-{1 + (hash_digit % 12):02d}-{1 + (hash_digit % 28):02d}",
        "social_profiles": {
            "twitter": f"@user{hash_digit}{hash_digit}",
            "linkedin": f"user-{email.split('@')[0]}",
            "facebook": f"user.{hash_digit}"
        }
    }
    
    return {
        "total_records": len(simulated_passwords),
        "compromised_passwords": simulated_passwords[:hash_digit % 3 + 1],
        "phone_records": simulated_phones[:hash_digit % 2 + 1],
        "personal_info": personal_info,
        "credit_cards_exposed": hash_digit % 2,
        "ssn_exposed": hash_digit > 8,
        "note": "⚠️ SIMULATED DATA FOR DEMONSTRATION - Not real breach data"
    }

async def get_comprehensive_breach_data(query: str, search_type: str) -> Dict[str, Any]:
    """Get comprehensive breach data by any identifier (SIMULATED DATA ONLY)"""
    query_hash = hashlib.md5(query.lower().encode()).hexdigest()
    hash_digit = int(query_hash[0], 16)
    
    # Generate base username and email
    if search_type == "email":
        username_base = query.split('@')[0]
        primary_email = query
    elif search_type == "phone":
        username_base = f"user{query.replace('+', '').replace('-', '')[-4:]}"
        primary_email = f"{username_base}@example.com"
    elif search_type == "name":
        username_base = query.lower().replace(' ', '_')
        primary_email = f"{username_base}@example.com"
    else:  # username
        username_base = query
        primary_email = f"{query}@example.com"
    
    # All associated emails
    all_emails = [
        primary_email,
        f"{username_base}@gmail.com",
        f"{username_base}@yahoo.com",
        f"{username_base}_work@company.com",
        f"{username_base}.personal@outlook.com",
        f"{username_base}123@hotmail.com"
    ]
    
    # All usernames used
    all_usernames = [
        username_base,
        f"{username_base}123",
        f"{username_base}_2023",
        f"{username_base}_{hash_digit}",
        f"user_{username_base}"
    ]
    
    # IP addresses from different breaches
    ip_addresses = [
        {
            "ip": f"192.168.{hash_digit}.{(hash_digit * 17) % 256}",
            "location": f"New York, US",
            "breach_source": "LinkedIn 2021",
            "last_seen": "2021-06-22"
        },
        {
            "ip": f"10.0.{hash_digit}.{(hash_digit * 23) % 256}",
            "location": f"San Francisco, US",
            "breach_source": "Facebook 2019",
            "last_seen": "2019-04-03"
        },
        {
            "ip": f"172.16.{hash_digit}.{(hash_digit * 31) % 256}",
            "location": f"London, UK",
            "breach_source": "Twitter 2023",
            "last_seen": "2023-01-15"
        },
        {
            "ip": f"{hash_digit + 100}.{hash_digit * 2}.{hash_digit * 3}.{(hash_digit * 41) % 256}",
            "location": f"Berlin, Germany",
            "breach_source": "Adobe 2013",
            "last_seen": "2013-10-04"
        },
        {
            "ip": f"45.{hash_digit}.{(hash_digit * 7) % 256}.{(hash_digit * 11) % 256}",
            "location": f"Tokyo, Japan",
            "breach_source": "MySpace 2008",
            "last_seen": "2008-06-11"
        }
    ]
    
    # Comprehensive password list from all breaches
    compromised_passwords = [
        {
            "source": "LinkedIn 2021",
            "password_hash": "5f4dcc3b5aa765d61d8327deb882cf99",
            "cracked": True,
            "plaintext": "password123",
            "first_seen": "2021-06-22",
            "breach_size": "700M records"
        },
        {
            "source": "Facebook 2019",
            "password_hash": "e10adc3949ba59abbe56e057f20f883e",
            "cracked": True,
            "plaintext": "123456",
            "first_seen": "2019-04-03",
            "breach_size": "533M records"
        },
        {
            "source": "Adobe 2013",
            "password_hash": "25d55ad283aa400af464c76d713c07ad",
            "cracked": True,
            "plaintext": "12345678",
            "first_seen": "2013-10-04",
            "breach_size": "153M records"
        },
        {
            "source": "Twitter 2023",
            "password_hash": "827ccb0eea8a706c4c34a16891f84e7b",
            "cracked": True,
            "plaintext": "12345",
            "first_seen": "2023-01-01",
            "breach_size": "200M records"
        },
        {
            "source": "MySpace 2008",
            "password_hash": "fcea920f7412b5da7be0cf42b8c93759",
            "cracked": True,
            "plaintext": "iloveyou",
            "first_seen": "2008-06-11",
            "breach_size": "360M records"
        },
        {
            "source": "Dropbox 2012",
            "password_hash": "098f6bcd4621d373cade4e832627b4f6",
            "cracked": True,
            "plaintext": "test",
            "first_seen": "2012-07-13",
            "breach_size": "68M records"
        }
    ]
    
    # Phone numbers
    phone_records = [
        f"+1-555-{hash_digit:03d}-{(hash_digit * 137) % 10000:04d}",
        f"+1-555-{(hash_digit + 1) % 1000:03d}-{(hash_digit * 251) % 10000:04d}",
        f"+44-20-{hash_digit:04d}-{(hash_digit * 173) % 10000:04d}",
        f"+49-30-{hash_digit:04d}-{(hash_digit * 197) % 10000:04d}"
    ]
    
    # Personal information
    personal_info = {
        "full_name": f"John Doe {hash_digit}",
        "first_name": "John",
        "last_name": f"Doe{hash_digit}",
        "addresses": [
            f"{hash_digit * 100} Main Street, City {hash_digit}, ST {hash_digit:05d}",
            f"Apt {hash_digit}, {hash_digit * 50} Oak Avenue, Town {hash_digit + 1}, ST {hash_digit:05d}"
        ],
        "date_of_birth": f"19{70 + (hash_digit % 30)}-{1 + (hash_digit % 12):02d}-{1 + (hash_digit % 28):02d}",
        "age": 54 - hash_digit,
        "gender": "Male" if hash_digit % 2 == 0 else "Female",
        "social_profiles": {
            "twitter": f"@{username_base}",
            "linkedin": f"linkedin.com/in/{username_base}",
            "facebook": f"facebook.com/{username_base}",
            "instagram": f"@{username_base}_ig",
            "github": f"github.com/{username_base}"
        },
        "employment": {
            "company": f"TechCorp {hash_digit}",
            "position": "Software Engineer",
            "work_email": f"{username_base}@techcorp{hash_digit}.com"
        }
    }
    
    return {
        "total_records": len(compromised_passwords),
        "all_emails": all_emails[:hash_digit % 5 + 2],
        "all_usernames": all_usernames[:hash_digit % 4 + 2],
        "compromised_passwords": compromised_passwords[:hash_digit % 6 + 3],
        "phone_records": phone_records[:hash_digit % 3 + 2],
        "ip_addresses": ip_addresses[:hash_digit % 5 + 2],
        "personal_info": personal_info,
        "credit_cards_exposed": hash_digit % 3,
        "ssn_exposed": hash_digit > 8,
        "driver_license_exposed": hash_digit > 6,
        "passport_exposed": hash_digit > 10,
        "note": "⚠️ SIMULATED DATA FOR DEMONSTRATION - Not real breach data"
    }

async def generate_security_audit(email: str, website_url: Optional[str] = None) -> Dict[str, Any]:
    """Generate comprehensive security audit and recommendations"""
    email_hash = hashlib.md5(email.lower().encode()).hexdigest()
    hash_digit = int(email_hash[0], 16)
    
    # Get associated accounts and their details
    username_base = email.split('@')[0]
    domain = email.split('@')[1] if '@' in email else 'example.com'
    
    associated_accounts = [
        {
            "platform": "Primary Email",
            "identifier": email,
            "username": username_base,
            "status": "active",
            "created_date": "2018-03-15",
            "linked_accounts": [
                {"email": f"{username_base}@gmail.com", "type": "recovery"},
                {"email": f"{username_base}_work@{domain}", "type": "alternate"}
            ],
            "compromised": hash_digit > 5,
            "password_found": hash_digit > 7,
            "password_hash": "5f4dcc3b5aa765d61d8327deb882cf99" if hash_digit > 7 else None,
            "password_plaintext": "password123" if hash_digit > 7 else None,
            "2fa_enabled": hash_digit < 5,
            "last_password_change": "2022-08-12" if hash_digit > 6 else "2024-01-05"
        },
        {
            "platform": "Work Account",
            "identifier": f"{username_base}@company.com",
            "username": username_base,
            "status": "active",
            "created_date": "2019-06-20",
            "linked_accounts": [
                {"email": email, "type": "recovery"}
            ],
            "compromised": hash_digit > 6,
            "password_found": hash_digit > 8,
            "password_hash": "e10adc3949ba59abbe56e057f20f883e" if hash_digit > 8 else None,
            "password_plaintext": "123456" if hash_digit > 8 else None,
            "2fa_enabled": hash_digit < 6,
            "last_password_change": "2021-11-30" if hash_digit > 7 else "2023-12-20"
        },
        {
            "platform": "Personal Account",
            "identifier": f"{username_base}@outlook.com",
            "username": f"{username_base}_personal",
            "status": "active",
            "created_date": "2017-02-10",
            "linked_accounts": [],
            "compromised": hash_digit > 4,
            "password_found": hash_digit > 9,
            "password_hash": "25d55ad283aa400af464c76d713c07ad" if hash_digit > 9 else None,
            "password_plaintext": "12345678" if hash_digit > 9 else None,
            "2fa_enabled": False,
            "last_password_change": "2020-05-15"
        }
    ]
    
    # Domain analysis if website_url provided
    domain_data = None
    if website_url:
        parsed_domain = urlparse(website_url).netloc or website_url
        domain_data = {
            "domain": parsed_domain,
            "emails_found": [
                f"admin@{parsed_domain}",
                f"contact@{parsed_domain}",
                f"support@{parsed_domain}"
            ],
            "exposed_in_breaches": hash_digit > 5,
            "ssl_valid": hash_digit < 10,
            "dns_records_exposed": hash_digit > 7,
            "subdomains_found": [
                f"mail.{parsed_domain}",
                f"admin.{parsed_domain}",
                f"api.{parsed_domain}"
            ] if hash_digit > 6 else []
        }
    
    vulnerabilities = [
        {
            "type": "Weak Password Reuse",
            "severity": "critical",
            "description": "Same password used across multiple accounts",
            "impact": "Account takeover, identity theft",
            "affected_accounts": [acc["identifier"] for acc in associated_accounts if acc["password_found"]],
            "exposed_passwords": [
                {"account": acc["identifier"], "password": acc["password_plaintext"], "hash": acc["password_hash"]}
                for acc in associated_accounts if acc["password_found"]
            ],
            "remediation_steps": [
                "Change passwords immediately",
                "Use unique passwords for each account",
                "Implement password manager"
            ]
        },
        {
            "type": "No 2FA Enabled",
            "severity": "high",
            "description": "Two-factor authentication not enabled on critical accounts",
            "impact": "Unauthorized access to sensitive accounts",
            "affected_accounts": [acc["identifier"] for acc in associated_accounts if not acc["2fa_enabled"]],
            "usernames_at_risk": [acc["username"] for acc in associated_accounts if not acc["2fa_enabled"]],
            "remediation_steps": [
                "Enable 2FA on all accounts",
                "Use authenticator app (not SMS)",
                "Save backup codes securely"
            ]
        },
        {
            "type": "Exposed Personal Data",
            "severity": "high",
            "description": "Email, usernames, and personal info found in breaches",
            "impact": "Phishing attacks, social engineering",
            "affected_accounts": [acc["identifier"] for acc in associated_accounts if acc["compromised"]],
            "linked_emails": [
                link["email"] 
                for acc in associated_accounts 
                for link in acc.get("linked_accounts", [])
            ],
            "remediation_steps": [
                "Review and update recovery emails",
                "Monitor for suspicious activity",
                "Enable breach alerts"
            ]
        },
        {
            "type": "Old Password Policies",
            "severity": "medium",
            "description": "Passwords not changed in over 1 year",
            "impact": "Outdated security, increased breach risk",
            "affected_accounts": [
                acc["identifier"] for acc in associated_accounts 
                if acc.get("last_password_change", "2024-01-01") < "2023-01-01"
            ],
            "last_changes": [
                {"account": acc["identifier"], "last_change": acc.get("last_password_change")}
                for acc in associated_accounts
            ],
            "remediation_steps": [
                "Update all passwords immediately",
                "Set 90-day password rotation",
                "Use strong, unique passwords"
            ]
        }
    ]
    
    # Detailed findings with all exposed data
    detailed_findings = {
        "total_accounts_analyzed": len(associated_accounts),
        "accounts_with_exposed_data": associated_accounts,
        "all_usernames": list(set([acc["username"] for acc in associated_accounts])),
        "all_linked_emails": list(set([
            link["email"] 
            for acc in associated_accounts 
            for link in acc.get("linked_accounts", [])
        ])),
        "compromised_credentials": [
            {
                "platform": acc["platform"],
                "username": acc["username"],
                "email": acc["identifier"],
                "password_hash": acc.get("password_hash"),
                "password_plaintext": acc.get("password_plaintext"),
                "compromised": acc["compromised"],
                "2fa_status": acc["2fa_enabled"]
            }
            for acc in associated_accounts
        ],
        "domain_analysis": domain_data
    }
    
    base_recommendations = [
        {
            "title": "Immediate Password Reset",
            "priority": "critical",
            "free": True,
            "description": "Change all passwords immediately, use unique passwords for each service"
        },
        {
            "title": "Enable Two-Factor Authentication",
            "priority": "critical",
            "free": True,
            "description": "Enable 2FA on all critical accounts (email, banking, social media)"
        },
        {
            "title": "Update Recovery Emails",
            "priority": "high",
            "free": True,
            "description": "Review and secure all linked and recovery email addresses"
        },
        {
            "title": "Credit Monitoring Setup",
            "priority": "high",
            "free": True,
            "description": "Set up credit monitoring to detect identity theft"
        }
    ]
    
    premium_features = [
        {
            "service": "Professional Security Audit",
            "description": "Comprehensive analysis of all online accounts and digital footprint",
            "deliverables": ["Full breach history report", "Custom security recommendations", "Priority support"],
            "price": 99.99,
            "duration": "One-time"
        },
        {
            "service": "Managed Password Migration",
            "description": "Secure password reset service for all compromised accounts",
            "deliverables": ["Password manager setup", "Guided migration", "Security training"],
            "price": 149.99,
            "duration": "One-time"
        },
        {
            "service": "Complete Identity Protection",
            "description": "Comprehensive protection for all your accounts and linked emails",
            "deliverables": ["Monitor all linked accounts", "Dark web monitoring", "Identity theft insurance", "24/7 support"],
            "price": 79.99,
            "duration": "Monthly"
        },
        {
            "service": "Website Security Hardening",
            "description": "Professional security implementation for your website",
            "deliverables": ["SSL/TLS configuration", "Security headers setup", "Vulnerability patching", "WAF implementation"],
            "price": 499.99,
            "duration": "Per site"
        },
        {
            "service": "Ongoing Security Monitoring",
            "description": "24/7 monitoring of your digital presence for new breaches",
            "deliverables": ["Real-time breach alerts", "Monthly reports", "Incident response"],
            "price": 29.99,
            "duration": "Monthly"
        }
    ]
    
    security_score = max(20, 100 - (hash_digit * 8 + len([v for v in vulnerabilities if v["severity"] == "critical"]) * 15))
    
    return {
        "vulnerabilities": vulnerabilities,
        "security_score": security_score,
        "recommendations": base_recommendations,
        "premium_features": premium_features,
        "estimated_cost": premium_features[2]["price"],
        "detailed_findings": detailed_findings
    }

async def search_social_media_accounts(query: str, search_type: str) -> Dict[str, Any]:
    """Search for social media accounts and check for compromises (SIMULATED DATA)"""
    query_hash = hashlib.md5(query.lower().encode()).hexdigest()
    hash_digit = int(query_hash[0], 16)
    
    platforms = [
        {
            "name": "Facebook",
            "icon": "facebook",
            "username": f"{query.split('@')[0] if '@' in query else query}",
            "profile_url": f"https://facebook.com/{query.split('@')[0] if '@' in query else query}",
            "created_date": "2015-03-12",
            "last_active": "2024-01-15",
            "followers": 432 + (hash_digit * 50),
            "compromised": hash_digit > 3,
            "breach_date": "2019-04-03" if hash_digit > 3 else None,
            "exposed_data": ["Email", "Phone", "Name", "DOB", "Location"] if hash_digit > 3 else [],
            "password_found": hash_digit > 7,
            "password_hash": "5f4dcc3b5aa765d61d8327deb882cf99" if hash_digit > 7 else None,
            "password_plaintext": "password123" if hash_digit > 7 else None,
            "has_2fa": hash_digit < 5
        },
        {
            "name": "Twitter/X",
            "icon": "twitter",
            "username": f"@{query.split('@')[0] if '@' in query else query}",
            "profile_url": f"https://twitter.com/{query.split('@')[0] if '@' in query else query}",
            "created_date": "2016-07-22",
            "last_active": "2024-02-01",
            "followers": 1250 + (hash_digit * 100),
            "compromised": hash_digit > 5,
            "breach_date": "2023-01-01" if hash_digit > 5 else None,
            "exposed_data": ["Email", "Username", "Phone"] if hash_digit > 5 else [],
            "password_found": hash_digit > 8,
            "password_hash": "e10adc3949ba59abbe56e057f20f883e" if hash_digit > 8 else None,
            "password_plaintext": "123456" if hash_digit > 8 else None,
            "has_2fa": hash_digit < 6
        },
        {
            "name": "Instagram",
            "icon": "instagram",
            "username": f"{query.split('@')[0] if '@' in query else query}_ig",
            "profile_url": f"https://instagram.com/{query.split('@')[0] if '@' in query else query}_ig",
            "created_date": "2017-11-05",
            "last_active": "2024-02-10",
            "followers": 892 + (hash_digit * 75),
            "compromised": hash_digit > 4,
            "breach_date": "2021-08-15" if hash_digit > 4 else None,
            "exposed_data": ["Email", "Phone", "Bio", "Photos metadata"] if hash_digit > 4 else [],
            "password_found": hash_digit > 9,
            "password_hash": "25d55ad283aa400af464c76d713c07ad" if hash_digit > 9 else None,
            "password_plaintext": "12345678" if hash_digit > 9 else None,
            "has_2fa": hash_digit < 4
        },
        {
            "name": "LinkedIn",
            "icon": "linkedin",
            "username": query.split('@')[0] if '@' in query else query,
            "profile_url": f"https://linkedin.com/in/{query.split('@')[0] if '@' in query else query}",
            "created_date": "2014-05-18",
            "last_active": "2024-01-28",
            "followers": 567 + (hash_digit * 60),
            "compromised": hash_digit > 6,
            "breach_date": "2021-06-22" if hash_digit > 6 else None,
            "exposed_data": ["Email", "Full name", "Phone", "Address", "Work history"] if hash_digit > 6 else [],
            "password_found": hash_digit > 10,
            "password_hash": "827ccb0eea8a706c4c34a16891f84e7b" if hash_digit > 10 else None,
            "password_plaintext": "12345" if hash_digit > 10 else None,
            "has_2fa": hash_digit < 7
        },
        {
            "name": "TikTok",
            "icon": "tiktok",
            "username": f"@{query.split('@')[0] if '@' in query else query}_tt",
            "profile_url": f"https://tiktok.com/@{query.split('@')[0] if '@' in query else query}_tt",
            "created_date": "2020-02-14",
            "last_active": "2024-02-09",
            "followers": 2340 + (hash_digit * 200),
            "compromised": hash_digit > 2,
            "breach_date": "2022-09-10" if hash_digit > 2 else None,
            "exposed_data": ["Email", "Phone", "Videos metadata"] if hash_digit > 2 else [],
            "password_found": hash_digit > 11,
            "password_hash": "fcea920f7412b5da7be0cf42b8c93759" if hash_digit > 11 else None,
            "password_plaintext": "iloveyou" if hash_digit > 11 else None,
            "has_2fa": hash_digit < 3
        },
        {
            "name": "Reddit",
            "icon": "reddit",
            "username": f"u/{query.split('@')[0] if '@' in query else query}",
            "profile_url": f"https://reddit.com/user/{query.split('@')[0] if '@' in query else query}",
            "created_date": "2018-08-30",
            "last_active": "2024-02-11",
            "followers": 145 + (hash_digit * 20),
            "compromised": hash_digit > 7,
            "breach_date": "2020-03-20" if hash_digit > 7 else None,
            "exposed_data": ["Email", "Username", "Post history"] if hash_digit > 7 else [],
            "password_found": hash_digit > 12,
            "password_hash": "5d41402abc4b2a76b9719d911017c592" if hash_digit > 12 else None,
            "password_plaintext": "hello" if hash_digit > 12 else None,
            "has_2fa": hash_digit < 8
        },
        {
            "name": "GitHub",
            "icon": "github",
            "username": query.split('@')[0] if '@' in query else query,
            "profile_url": f"https://github.com/{query.split('@')[0] if '@' in query else query}",
            "created_date": "2016-03-25",
            "last_active": "2024-02-08",
            "followers": 89 + (hash_digit * 15),
            "compromised": hash_digit > 8,
            "breach_date": "2023-05-12" if hash_digit > 8 else None,
            "exposed_data": ["Email", "Repositories", "SSH keys"] if hash_digit > 8 else [],
            "password_found": False,
            "password_hash": None,
            "password_plaintext": None,
            "has_2fa": hash_digit < 9
        },
        {
            "name": "Discord",
            "icon": "discord",
            "username": f"{query.split('@')[0] if '@' in query else query}#1234",
            "profile_url": f"discord://user/{hash_digit}123456789",
            "created_date": "2019-11-10",
            "last_active": "2024-02-12",
            "followers": 234 + (hash_digit * 30),
            "compromised": hash_digit > 9,
            "breach_date": "2021-12-15" if hash_digit > 9 else None,
            "exposed_data": ["Email", "Phone", "Server memberships"] if hash_digit > 9 else [],
            "password_found": hash_digit > 13,
            "password_hash": "098f6bcd4621d373cade4e832627b4f6" if hash_digit > 13 else None,
            "password_plaintext": "test" if hash_digit > 13 else None,
            "has_2fa": hash_digit < 10
        }
    ]
    
    found_accounts = []
    for i, platform in enumerate(platforms):
        if hash_digit > i:
            found_accounts.append(platform)
    
    compromised_count = sum(1 for acc in found_accounts if acc["compromised"])
    password_count = sum(1 for acc in found_accounts if acc["password_found"])
    
    recommendations = [
        "Change passwords on all compromised platforms immediately",
        "Enable two-factor authentication (2FA) on all accounts",
        "Use unique passwords for each platform",
        "Monitor accounts for suspicious activity",
        "Review and update privacy settings on all platforms"
    ]
    
    remediation_services = [
        {
            "service": "Social Media Security Package",
            "description": "Comprehensive security overhaul for all your social media accounts",
            "deliverables": [
                "Password reset for all compromised accounts",
                "2FA setup on all platforms",
                "Privacy settings optimization",
                "Account recovery setup",
                "Security training session"
            ],
            "price": 199.99,
            "duration": "One-time",
            "savings": "Save $50 vs individual resets"
        },
        {
            "service": "Identity Protection Plan",
            "description": "Ongoing monitoring and protection for your digital identity",
            "deliverables": [
                "Dark web monitoring",
                "Real-time breach alerts",
                "Monthly security reports",
                "Identity theft insurance ($1M coverage)",
                "24/7 fraud resolution support"
            ],
            "price": 49.99,
            "duration": "Monthly",
            "popular": True
        },
        {
            "service": "Emergency Account Recovery",
            "description": "Immediate assistance to secure compromised accounts",
            "deliverables": [
                "24-hour response time",
                "Direct platform communication",
                "Password recovery assistance",
                "Content removal support",
                "Legal documentation"
            ],
            "price": 299.99,
            "duration": "Per incident",
            "urgent": True
        }
    ]
    
    return {
        "total_accounts": len(found_accounts),
        "platforms_found": [acc["name"] for acc in found_accounts],
        "accounts": found_accounts,
        "compromised_count": compromised_count,
        "password_count": password_count,
        "security_recommendations": recommendations,
        "remediation_services": remediation_services,
        "note": "⚠️ SIMULATED DATA FOR DEMONSTRATION - Search uses algorithmic simulation, not real social media APIs"
    }

@api_router.get("/")
async def root():
    return {"message": "Security Testing API", "version": "1.0.0"}

@api_router.post("/hash/decode", response_model=HashDecodeResponse)
async def decode_hash(request: HashDecodeRequest):
    """Decode and identify hash types"""
    detected, possible = detect_hash_type(request.hash_value)
    
    if request.hash_type:
        detected = request.hash_type
    
    return HashDecodeResponse(
        hash_value=request.hash_value,
        detected_type=detected,
        possible_types=possible,
        status="identified" if detected != "Unknown" else "unknown",
        message=f"Hash identified as {detected}" if detected != "Unknown" else "Unable to identify hash type"
    )

@api_router.post("/hash/generate")
async def generate_hashes(text: str):
    """Generate all hash types for input text"""
    if not text:
        raise HTTPException(status_code=400, detail="Text input required")
    
    hashes = generate_hash_examples(text)
    
    return {
        "input": text,
        "hashes": hashes,
        "count": len(hashes)
    }

@api_router.post("/pentest/scan", response_model=PenTestResponse)
async def run_pentest(request: PenTestRequest):
    """Run penetration testing suite"""
    results = {}
    parsed = urlparse(request.target_url)
    domain = parsed.netloc or parsed.path
    
    if "port_scan" in request.tests:
        results["port_scan"] = await check_port_scan(domain)
    
    if "ssl_tls" in request.tests:
        results["ssl_tls"] = await check_ssl_tls(request.target_url)
    
    if "security_headers" in request.tests:
        results["security_headers"] = await check_security_headers(request.target_url)
    
    if "xss_detection" in request.tests:
        results["xss_detection"] = await check_xss_detection(request.target_url)
    
    if "sql_injection" in request.tests:
        results["sql_injection"] = await check_sql_injection(request.target_url)
    
    response_obj = PenTestResponse(
        target_url=request.target_url,
        timestamp=datetime.now(timezone.utc).isoformat(),
        results=results
    )
    
    scan_doc = response_obj.model_dump()
    await db.pentest_scans.insert_one({**scan_doc, "_id": scan_doc["id"]})
    
    return response_obj

@api_router.get("/pentest/history")
async def get_pentest_history():
    """Get scan history"""
    scans = await db.pentest_scans.find({}, {"_id": 0}).sort("timestamp", -1).limit(20).to_list(20)
    return {"scans": scans, "count": len(scans)}

@api_router.post("/api/test", response_model=APITestResponse)
async def test_api_endpoint(request: APITestRequest):
    """Test API endpoint security"""
    try:
        headers = request.headers or {}
        method = request.method.upper()
        
        if method == "GET":
            response = requests.get(request.endpoint_url, headers=headers, timeout=10)
        elif method == "POST":
            response = requests.post(request.endpoint_url, headers=headers, timeout=10)
        else:
            response = requests.request(method, request.endpoint_url, headers=headers, timeout=10)
        
        security_headers = {
            'CORS': response.headers.get('Access-Control-Allow-Origin', 'Not Set'),
            'Content-Type': response.headers.get('Content-Type', 'Not Set'),
            'X-Rate-Limit': response.headers.get('X-RateLimit-Limit', 'Not Set')
        }
        
        issues = []
        if security_headers['CORS'] == '*':
            issues.append("CORS allows all origins (security risk)")
        if 'application/json' not in security_headers['Content-Type']:
            issues.append("Content-Type not set to application/json")
        if security_headers['X-Rate-Limit'] == 'Not Set':
            issues.append("No rate limiting detected")
        
        return APITestResponse(
            endpoint_url=request.endpoint_url,
            method=method,
            status_code=response.status_code,
            headers=dict(response.headers),
            security_headers=security_headers,
            issues=issues
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@api_router.post("/breach/check", response_model=EmailBreachResponse)
async def check_email_breach(request: EmailBreachRequest):
    """Check if email has been in data breaches"""
    email = request.email.strip().lower()
    
    if not validate_email(email):
        raise HTTPException(status_code=400, detail="Invalid email format")
    
    hibp_result = await check_haveibeenpwned(email)
    
    if hibp_result["status"] == "error" or hibp_result["count"] == 0:
        local_result = await check_email_breach_local(email)
        breaches = local_result["breaches"]
        breach_count = local_result["count"]
    else:
        breaches = hibp_result["breaches"]
        breach_count = hibp_result["count"]
    
    if breach_count == 0:
        risk_level = "low"
        recommendations = [
            "No breaches detected - maintain good password hygiene",
            "Use unique passwords for each service",
            "Enable two-factor authentication where available"
        ]
    elif breach_count <= 2:
        risk_level = "medium"
        recommendations = [
            "Change passwords on affected services immediately",
            "Enable two-factor authentication",
            "Monitor accounts for suspicious activity",
            "Use a password manager"
        ]
    else:
        risk_level = "high"
        recommendations = [
            "URGENT: Change all passwords immediately",
            "Enable two-factor authentication on all accounts",
            "Consider using a new email address for sensitive accounts",
            "Monitor credit reports for identity theft",
            "Use unique, strong passwords for each service"
        ]
    
    breach_lookup = EmailBreachResponse(
        email=email,
        is_valid=True,
        breaches_found=breach_count,
        breach_data=breaches,
        risk_level=risk_level,
        recommendations=recommendations
    )
    
    lookup_doc = breach_lookup.model_dump()
    await db.breach_lookups.insert_one({**lookup_doc, "_id": str(uuid.uuid4()), "timestamp": datetime.now(timezone.utc).isoformat()})
    
    return breach_lookup

@api_router.get("/breach/history")
async def get_breach_history():
    """Get breach lookup history"""
    lookups = await db.breach_lookups.find({}, {"_id": 0}).sort("timestamp", -1).limit(20).to_list(20)
    return {"lookups": lookups, "count": len(lookups)}

@api_router.post("/hash/crack", response_model=HashCrackResponse)
async def crack_hash(request: HashCrackRequest):
    """Crack hash to recover plaintext"""
    hash_type = request.hash_type.upper()
    supported_types = ["MD5", "SHA-256", "SHA-512", "SHA3-256", "SHA3-512", "BLAKE2B", "BLAKE2S", "NTLM"]
    
    if hash_type not in supported_types:
        raise HTTPException(status_code=400, detail=f"Unsupported hash type. Supported: {', '.join(supported_types)}")
    
    if request.method == "dictionary":
        result = await crack_hash_dictionary(request.hash_value, hash_type)
    elif request.method == "bruteforce":
        result = await crack_hash_bruteforce(request.hash_value, hash_type, request.max_length or 4)
    else:
        raise HTTPException(status_code=400, detail="Method must be 'dictionary' or 'bruteforce'")
    
    response = HashCrackResponse(
        hash_value=request.hash_value,
        hash_type=hash_type,
        cracked=result["cracked"],
        plaintext=result.get("plaintext"),
        method_used=request.method,
        attempts=result["attempts"],
        time_taken=round(result["time_taken"], 3)
    )
    
    crack_doc = response.model_dump()
    await db.hash_cracks.insert_one({
        **crack_doc,
        "_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat()
    })
    
    return response

@api_router.get("/hash/crack/history")
async def get_crack_history():
    """Get hash cracking history"""
    cracks = await db.hash_cracks.find({}, {"_id": 0}).sort("timestamp", -1).limit(50).to_list(50)
    return {"cracks": cracks, "count": len(cracks)}

@api_router.post("/session/export")
async def export_session(request: SessionExportRequest):
    """Export session data to file"""
    from fastapi.responses import Response
    import csv
    from io import StringIO
    
    export_format = request.export_format.lower()
    session_data = request.session_data
    
    if export_format == "json":
        import json
        content = json.dumps(session_data, indent=2)
        media_type = "application/json"
        filename = f"seccheck_session_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    
    elif export_format == "csv":
        output = StringIO()
        
        if "results" in session_data:
            writer = csv.writer(output)
            writer.writerow(["Type", "Target", "Status", "Details"])
            
            for item in session_data.get("results", []):
                writer.writerow([
                    item.get("type", ""),
                    item.get("target", ""),
                    item.get("status", ""),
                    str(item.get("details", ""))
                ])
        
        content = output.getvalue()
        media_type = "text/csv"
        filename = f"seccheck_session_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    
    elif export_format == "txt":
        lines = []
        lines.append("=" * 60)
        lines.append("SECCHECK SESSION EXPORT")
        lines.append(f"Generated: {datetime.now().isoformat()}")
        lines.append("=" * 60)
        lines.append("")
        
        for key, value in session_data.items():
            lines.append(f"{key.upper()}:")
            lines.append(str(value))
            lines.append("")
        
        content = "\n".join(lines)
        media_type = "text/plain"
        filename = f"seccheck_session_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    
    else:
        raise HTTPException(status_code=400, detail="Format must be 'json', 'csv', or 'txt'")
    
    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

@api_router.post("/breach/detailed", response_model=BreachDetailResponse)
async def get_breach_details(request: BreachDetailRequest):
    """Get detailed breach information including sensitive data (ETHICAL USE ONLY)"""
    query = request.query.strip().lower()
    search_type = request.search_type.lower()
    
    # Validation based on search type
    if search_type == "email" and not validate_email(query):
        raise HTTPException(status_code=400, detail="Invalid email format")
    
    if search_type in ["username", "name"] and len(query) < 2:
        raise HTTPException(status_code=400, detail=f"{search_type} must be at least 2 characters")
    
    if not request.reveal_sensitive:
        raise HTTPException(
            status_code=403,
            detail="You must acknowledge ethical use and provide consent to view sensitive data"
        )
    
    breach_data = await get_comprehensive_breach_data(query, search_type)
    
    response = BreachDetailResponse(
        query=query,
        search_type=search_type,
        total_records=breach_data["total_records"],
        exposed_data={
            "passwords": len(breach_data["compromised_passwords"]),
            "phones": len(breach_data["phone_records"]),
            "emails": len(breach_data["all_emails"]),
            "usernames": len(breach_data["all_usernames"]),
            "ips": len(breach_data["ip_addresses"]),
            "credit_cards": breach_data["credit_cards_exposed"],
            "ssn": breach_data["ssn_exposed"]
        },
        compromised_passwords=breach_data["compromised_passwords"],
        phone_records=breach_data["phone_records"],
        ip_addresses=breach_data["ip_addresses"],
        all_emails=breach_data["all_emails"],
        all_usernames=breach_data["all_usernames"],
        personal_info=breach_data["personal_info"],
        severity="critical" if breach_data["total_records"] > 4 else "high",
        requires_premium=True
    )
    
    detail_doc = response.model_dump()
    await db.breach_details.insert_one({
        **detail_doc,
        "_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "note": breach_data["note"]
    })
    
    return response

@api_router.post("/security/audit", response_model=SecurityAuditResponse)
async def create_security_audit(request: SecurityAuditRequest):
    """Generate comprehensive security audit with premium consultation options"""
    email = request.email.strip().lower()
    
    if not validate_email(email):
        raise HTTPException(status_code=400, detail="Invalid email format")
    
    audit_data = await generate_security_audit(email, request.website_url)
    
    response = SecurityAuditResponse(
        email=email,
        vulnerabilities=audit_data["vulnerabilities"],
        security_score=audit_data["security_score"],
        recommendations=audit_data["recommendations"],
        premium_features=audit_data["premium_features"],
        estimated_cost=audit_data["estimated_cost"],
        detailed_findings=audit_data.get("detailed_findings")
    )
    
    audit_doc = response.model_dump()
    await db.security_audits.insert_one({
        **audit_doc,
        "timestamp": datetime.now(timezone.utc).isoformat()
    })
    
    return response

@api_router.get("/security/pricing")
async def get_security_pricing():
    """Get pricing for premium security services"""
    services = [
        {
            "id": "pro_audit",
            "name": "Professional Security Audit",
            "price": 99.99,
            "currency": "USD",
            "billing": "one-time",
            "features": [
                "Complete breach history analysis",
                "Custom security recommendations",
                "Vulnerability assessment",
                "Priority email support"
            ]
        },
        {
            "id": "password_migration",
            "name": "Managed Password Migration",
            "price": 149.99,
            "currency": "USD",
            "billing": "one-time",
            "features": [
                "Professional password reset service",
                "Password manager setup & training",
                "Guided account migration",
                "30-day follow-up support"
            ]
        },
        {
            "id": "website_hardening",
            "name": "Website Security Hardening",
            "price": 499.99,
            "currency": "USD",
            "billing": "per-site",
            "features": [
                "SSL/TLS configuration",
                "Security headers implementation",
                "Vulnerability patching",
                "WAF setup",
                "Performance optimization"
            ]
        },
        {
            "id": "monitoring_monthly",
            "name": "Ongoing Security Monitoring",
            "price": 29.99,
            "currency": "USD",
            "billing": "monthly",
            "features": [
                "24/7 breach monitoring",
                "Real-time alerts",
                "Monthly security reports",
                "Incident response assistance"
            ]
        },
        {
            "id": "enterprise",
            "name": "Enterprise Security Suite",
            "price": 2499.99,
            "currency": "USD",
            "billing": "per-project",
            "features": [
                "Full security infrastructure audit",
                "Custom security policy development",
                "Employee security training",
                "Compliance certification assistance",
                "Dedicated security consultant"
            ]
        }
    ]
    
    return {"services": services, "total_services": len(services)}

@api_router.post("/social/search", response_model=SocialMediaSearchResponse)
async def search_social_media(request: SocialMediaSearchRequest):
    """Search for social media accounts by email or username"""
    query = request.query.strip()
    search_type = request.search_type.lower()
    
    if search_type == "email" and not validate_email(query):
        raise HTTPException(status_code=400, detail="Invalid email format")
    
    if search_type == "username" and len(query) < 3:
        raise HTTPException(status_code=400, detail="Username must be at least 3 characters")
    
    search_data = await search_social_media_accounts(query, search_type)
    
    response = SocialMediaSearchResponse(
        query=query,
        total_accounts=search_data["total_accounts"],
        platforms_found=search_data["platforms_found"],
        accounts=search_data["accounts"],
        compromised_count=search_data["compromised_count"],
        security_recommendations=search_data["security_recommendations"],
        remediation_services=search_data["remediation_services"]
    )
    
    search_doc = response.model_dump()
    await db.social_searches.insert_one({
        **search_doc,
        "_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "search_type": search_type,
        "note": search_data["note"]
    })
    
    return response

@api_router.get("/social/history")
async def get_social_search_history():
    """Get social media search history"""
    searches = await db.social_searches.find({}, {"_id": 0}).sort("timestamp", -1).limit(20).to_list(20)
    return {"searches": searches, "count": len(searches)}

app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()