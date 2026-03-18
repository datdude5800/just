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