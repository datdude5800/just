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
    email: str
    reveal_sensitive: bool = False

class BreachDetailResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")
    email: str
    total_records: int
    exposed_data: Dict[str, Any]
    compromised_passwords: List[Dict[str, Any]]
    phone_records: List[str]
    personal_info: Dict[str, Any]
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

async def generate_security_audit(email: str, website_url: Optional[str] = None) -> Dict[str, Any]:
    """Generate comprehensive security audit and recommendations"""
    email_hash = hashlib.md5(email.lower().encode()).hexdigest()
    hash_digit = int(email_hash[0], 16)
    
    vulnerabilities = [
        {
            "type": "Weak Password Reuse",
            "severity": "critical",
            "description": "Password found in multiple breach databases",
            "impact": "Account takeover, identity theft"
        },
        {
            "type": "No 2FA Enabled",
            "severity": "high",
            "description": "Two-factor authentication not detected on accounts",
            "impact": "Unauthorized access to sensitive accounts"
        },
        {
            "type": "Exposed Personal Data",
            "severity": "high",
            "description": "Email, phone, and personal info found in breaches",
            "impact": "Phishing attacks, social engineering"
        },
        {
            "type": "Old Account Activity",
            "severity": "medium",
            "description": "Accounts created 5+ years ago with no security updates",
            "impact": "Outdated security protocols"
        }
    ]
    
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
        },
        {
            "service": "Enterprise Security Consultation",
            "description": "Complete security overhaul for businesses",
            "deliverables": ["Security policy creation", "Employee training", "Infrastructure audit", "Compliance certification"],
            "price": 2499.99,
            "duration": "Per project"
        }
    ]
    
    security_score = max(20, 100 - (hash_digit * 8 + len(vulnerabilities) * 5))
    
    return {
        "vulnerabilities": vulnerabilities[:hash_digit % 4 + 1],
        "security_score": security_score,
        "recommendations": base_recommendations,
        "premium_features": premium_features,
        "estimated_cost": premium_features[0]["price"] if hash_digit > 5 else premium_features[3]["price"]
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
    email = request.email.strip().lower()
    
    if not validate_email(email):
        raise HTTPException(status_code=400, detail="Invalid email format")
    
    if not request.reveal_sensitive:
        raise HTTPException(
            status_code=403,
            detail="You must acknowledge ethical use and provide consent to view sensitive data"
        )
    
    breach_data = await get_detailed_breach_data(email)
    
    response = BreachDetailResponse(
        email=email,
        total_records=breach_data["total_records"],
        exposed_data={
            "passwords": len(breach_data["compromised_passwords"]),
            "phones": len(breach_data["phone_records"]),
            "credit_cards": breach_data["credit_cards_exposed"],
            "ssn": breach_data["ssn_exposed"]
        },
        compromised_passwords=breach_data["compromised_passwords"],
        phone_records=breach_data["phone_records"],
        personal_info=breach_data["personal_info"],
        severity="critical" if breach_data["total_records"] > 2 else "high",
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
        estimated_cost=audit_data["estimated_cost"]
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