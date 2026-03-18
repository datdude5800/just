"""
Comprehensive Breach Search Engine
Deep searches across multiple sources, cross-references data, finds connected emails
"""

import asyncio
import hashlib
from typing import Dict, List, Set, Any

async def deep_search_breaches(db, query: str, search_type: str, max_depth: int = 3) -> Dict[str, Any]:
    """
    Deep recursive search across all data sources
    Finds connected emails and searches them recursively
    """
    
    searched_items = set()
    all_results = {
        "emails": set(),
        "usernames": set(),
        "phones": set(),
        "passwords": [],
        "ips": [],
        "personal_info": {},
        "breaches": [],
        "connections": []
    }
    
    # Start recursive search
    await recursive_breach_search(db, query, search_type, 0, max_depth, searched_items, all_results)
    
    # Convert sets to lists for JSON serialization
    return {
        "total_emails": len(all_results["emails"]),
        "total_usernames": len(all_results["usernames"]),
        "total_passwords": len(all_results["passwords"]),
        "total_ips": len(all_results["ips"]),
        "search_depth": max_depth,
        "items_searched": len(searched_items),
        "all_emails": list(all_results["emails"]),
        "all_usernames": list(all_results["usernames"]),
        "all_phones": list(all_results["phones"]),
        "compromised_passwords": all_results["passwords"],
        "ip_addresses": all_results["ips"],
        "personal_info": all_results["personal_info"],
        "breach_sources": all_results["breaches"],
        "connection_map": all_results["connections"]
    }

async def recursive_breach_search(db, query: str, search_type: str, current_depth: int, max_depth: int, 
                                  searched_items: Set, results: Dict):
    """Recursively search for breaches and connected data"""
    
    # Prevent infinite loops
    if current_depth >= max_depth or query in searched_items:
        return
    
    searched_items.add(query)
    
    # Search in breach_data collection
    search_query = build_search_query(query, search_type)
    breach_records = await db.breach_data.find(search_query, {"_id": 0}).to_list(100)
    
    # Search in social_accounts collection
    social_accounts = await db.social_accounts.find(search_query, {"_id": 0}).to_list(100)
    
    # Search in breach_details collection (historical searches)
    breach_details = await db.breach_details.find(search_query, {"_id": 0}).to_list(100)
    
    # Aggregate all found data
    for record in breach_records + breach_details:
        # Extract emails
        if record.get("email"):
            results["emails"].add(record["email"])
        if record.get("all_emails"):
            results["emails"].update(record["all_emails"])
        
        # Extract usernames
        if record.get("username"):
            results["usernames"].add(record["username"])
        if record.get("all_usernames"):
            results["usernames"].update(record["all_usernames"])
        
        # Extract phones
        if record.get("phone"):
            results["phones"].add(record["phone"])
        if record.get("phone_records"):
            results["phones"].update(record["phone_records"])
        
        # Extract passwords
        if record.get("compromised_passwords"):
            results["passwords"].extend(record["compromised_passwords"])
        
        # Extract IPs
        if record.get("ip_addresses"):
            results["ips"].extend(record["ip_addresses"])
        
        # Extract personal info
        if record.get("personal_info") and not results["personal_info"]:
            results["personal_info"] = record["personal_info"]
        
        # Track breach sources
        if record.get("compromised_passwords"):
            for pwd in record["compromised_passwords"]:
                if pwd.get("source") not in [b["source"] for b in results["breaches"]]:
                    results["breaches"].append({
                        "source": pwd.get("source", "Unknown"),
                        "date": pwd.get("first_seen", "Unknown")
                    })
    
    # Extract from social accounts
    for account in social_accounts:
        if account.get("email"):
            results["emails"].add(account["email"])
        if account.get("username"):
            results["usernames"].add(account["username"])
        if account.get("phone"):
            results["phones"].add(account["phone"])
        
        if account.get("password_plaintext"):
            results["passwords"].append({
                "source": f"{account.get('platform', 'Unknown')} Breach",
                "password_hash": account.get("password_hash", ""),
                "plaintext": account.get("password_plaintext", ""),
                "cracked": True,
                "first_seen": account.get("breach_date", "Unknown"),
                "breach_size": "Social Media"
            })
    
    # Record connection
    results["connections"].append({
        "query": query,
        "type": search_type,
        "depth": current_depth,
        "found_emails": len([e for e in results["emails"] if e not in searched_items]),
        "found_usernames": len([u for u in results["usernames"] if u not in searched_items])
    })
    
    # Recursively search connected emails (depth + 1)
    if current_depth < max_depth - 1:
        # Search all newly found emails
        for email in list(results["emails"]):
            if email not in searched_items:
                await recursive_breach_search(db, email, "email", current_depth + 1, max_depth, searched_items, results)
        
        # Search all newly found usernames
        for username in list(results["usernames"]):
            if username not in searched_items:
                await recursive_breach_search(db, username, "username", current_depth + 1, max_depth, searched_items, results)

def build_search_query(query: str, search_type: str) -> Dict:
    """Build MongoDB search query"""
    if search_type == "email":
        return {"$or": [
            {"email": {"$regex": query, "$options": "i"}},
            {"all_emails": {"$regex": query, "$options": "i"}}
        ]}
    elif search_type == "username":
        return {"$or": [
            {"username": {"$regex": query, "$options": "i"}},
            {"all_usernames": {"$regex": query, "$options": "i"}}
        ]}
    elif search_type == "phone":
        return {"$or": [
            {"phone": query},
            {"phone_records": query}
        ]}
    elif search_type == "name":
        return {"$or": [
            {"personal_info.full_name": {"$regex": query, "$options": "i"}},
            {"personal_info.first_name": {"$regex": query, "$options": "i"}},
            {"personal_info.last_name": {"$regex": query, "$options": "i"}}
        ]}
    else:
        return {}

async def search_external_sources(query: str, search_type: str) -> Dict[str, Any]:
    """
    Search external breach databases (Have I Been Pwned, etc.)
    This would integrate with real APIs
    """
    
    external_results = {
        "sources_searched": [],
        "breaches_found": [],
        "total_breaches": 0
    }
    
    # Example: Have I Been Pwned integration
    # Requires API key in environment
    hibp_api_key = None  # Would get from environment
    
    if search_type == "email" and hibp_api_key:
        # Would make real API call here
        external_results["sources_searched"].append("Have I Been Pwned")
        # API call would go here
    
    # Example: DeHashed integration
    # Would require subscription and API key
    external_results["sources_searched"].append("Internal Database (Primary)")
    
    # Placeholder for future integrations:
    # - LeakCheck.io
    # - Intelligence X
    # - Snusbase
    # - WeLeakInfo archive
    
    return external_results

async def cross_reference_data(all_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Cross-reference all found data to find patterns and connections
    """
    
    cross_refs = {
        "password_reuse": [],
        "linked_accounts": [],
        "ip_matches": [],
        "pattern_analysis": {}
    }
    
    # Find password reuse patterns
    password_map = {}
    for pwd in all_data.get("compromised_passwords", []):
        pw = pwd.get("plaintext", "")
        if pw:
            if pw not in password_map:
                password_map[pw] = []
            password_map[pw].append(pwd.get("source", "Unknown"))
    
    for password, sources in password_map.items():
        if len(sources) > 1:
            cross_refs["password_reuse"].append({
                "password": password,
                "used_in": sources,
                "reuse_count": len(sources),
                "risk_level": "CRITICAL"
            })
    
    # Find linked accounts (same email in multiple sources)
    email_sources = {}
    for email in all_data.get("all_emails", []):
        # Would track which breach sources this email appears in
        pass
    
    # IP address correlation
    ip_map = {}
    for ip_data in all_data.get("ip_addresses", []):
        ip = ip_data.get("ip", "")
        if ip:
            if ip not in ip_map:
                ip_map[ip] = []
            ip_map[ip].append(ip_data.get("breach_source", "Unknown"))
    
    for ip, sources in ip_map.items():
        if len(sources) > 1:
            cross_refs["ip_matches"].append({
                "ip_address": ip,
                "seen_in_breaches": sources,
                "correlation": "Multiple breach sources"
            })
    
    return cross_refs
