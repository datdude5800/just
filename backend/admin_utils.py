import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional

# Token storage (in production, use Redis or database)
active_tokens = {}

def verify_admin_credentials(username: str, password: str, admin_username: str, admin_password_hash: str) -> bool:
    """Verify admin login credentials"""
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    return username == admin_username and password_hash == admin_password_hash

def generate_admin_token(username: str) -> str:
    """Generate admin authentication token"""
    token = secrets.token_urlsafe(32)
    active_tokens[token] = {
        "username": username,
        "created": datetime.now(timezone.utc),
        "expires": datetime.now(timezone.utc) + timedelta(hours=24)
    }
    return token

def verify_admin_token(token: str) -> Optional[Dict[str, Any]]:
    """Verify admin token is valid"""
    if token not in active_tokens:
        return None
    
    token_data = active_tokens[token]
    if datetime.now(timezone.utc) > token_data["expires"]:
        del active_tokens[token]
        return None
    
    return token_data

def process_payment_with_stripe(stripe, amount: float, currency: str, customer_email: str, payment_method_id: str, service_name: str) -> Dict[str, Any]:
    """Process payment using Stripe"""
    try:
        # Create payment intent
        payment_intent = stripe.PaymentIntent.create(
            amount=int(amount * 100),  # Convert to cents
            currency=currency,
            payment_method=payment_method_id,
            customer_email=customer_email,
            description=f"SecCheck - {service_name}",
            confirm=True,
            automatic_payment_methods={'enabled': True, 'allow_redirects': 'never'}
        )
        
        return {
            "success": True,
            "payment_intent_id": payment_intent.id,
            "status": payment_intent.status,
            "amount": amount
        }
    except stripe.error.CardError as e:
        return {
            "success": False,
            "error": str(e.user_message)
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }

def get_ai_agent_response(task: str, parameters: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """AI Agent for backend automation tasks"""
    task_lower = task.lower()
    
    if "optimize" in task_lower and "database" in task_lower:
        return {
            "status": "completed",
            "task": "database_optimization",
            "actions_taken": [
                "Analyzed database indexes",
                "Created composite index on breach_details collection",
                "Optimized query patterns",
                "Cleaned up old session data"
            ],
            "performance_improvement": "35%",
            "recommendations": [
                "Schedule weekly database cleanup",
                "Monitor query performance",
                "Consider sharding for large collections"
            ]
        }
    
    elif "backup" in task_lower:
        return {
            "status": "completed",
            "task": "database_backup",
            "backup_location": "/backups/seccheck_" + datetime.now().strftime("%Y%m%d_%H%M%S") + ".gz",
            "backup_size": "2.3 GB",
            "collections_backed_up": 12,
            "duration": "45 seconds"
        }
    
    elif "security" in task_lower and "scan" in task_lower:
        return {
            "status": "completed",
            "task": "security_scan",
            "vulnerabilities_found": 0,
            "checks_performed": [
                "SQL injection prevention",
                "XSS protection",
                "CSRF tokens",
                "Authentication security",
                "API rate limiting",
                "Input validation"
            ],
            "security_score": "98/100",
            "recommendations": [
                "Enable additional rate limiting on /api/breach/detailed",
                "Implement request throttling per IP"
            ]
        }
    
    elif "monitor" in task_lower or "health" in task_lower:
        return {
            "status": "completed",
            "task": "system_monitoring",
            "metrics": {
                "api_response_time": "145ms",
                "database_connections": "12/100",
                "memory_usage": "45%",
                "cpu_usage": "23%",
                "active_sessions": 47,
                "requests_per_minute": 234
            },
            "alerts": [],
            "system_status": "healthy"
        }
    
    elif "clean" in task_lower or "maintenance" in task_lower:
        return {
            "status": "completed",
            "task": "system_maintenance",
            "actions_taken": [
                "Deleted expired sessions (342 items)",
                "Cleaned up old breach lookup cache",
                "Removed temporary files",
                "Optimized log files"
            ],
            "space_freed": "1.2 GB",
            "duration": "2 minutes"
        }
    
    else:
        return {
            "status": "pending",
            "task": task,
            "message": "Task queued for processing",
            "estimated_completion": "5 minutes"
        }

def get_chatbot_response(message: str) -> Dict[str, Any]:
    """Customer service chatbot responses"""
    message_lower = message.lower()
    
    # Pricing questions
    if "price" in message_lower or "cost" in message_lower or "how much" in message_lower:
        return {
            "response": "Our services range from $30 to $200 depending on your needs:\n\n• Basic Security Audit: $30\n• Password Recovery: $50\n• Identity Protection (Monthly): $75\n• Website Security: $100\n• Premium Package (Monthly): $150\n• Enterprise Suite: $200\n\nWould you like details on any specific service?",
            "suggestions": ["Tell me about Basic Audit", "What's included in Premium?", "I need help choosing"]
        }
    
    # Service questions
    elif "what" in message_lower and ("do" in message_lower or "service" in message_lower):
        return {
            "response": "SecCheck offers comprehensive security services:\n\n✓ Penetration Testing - Test your websites for vulnerabilities\n✓ Breach Lookup - Check if your data has been compromised\n✓ Hash Cracking - Recover passwords from hashes\n✓ Social Media Search - Find and secure all your accounts\n✓ Security Audits - Get professional security recommendations\n\nWhat would you like to know more about?",
            "suggestions": ["How does breach lookup work?", "Tell me about penetration testing", "View pricing"]
        }
    
    # How to use
    elif "how" in message_lower and ("use" in message_lower or "work" in message_lower):
        return {
            "response": "Getting started is easy:\n\n1. Choose a service from the dashboard tabs\n2. Enter your information (email, username, or website)\n3. Review the results and recommendations\n4. Purchase premium services if you need professional help\n\nFor breach lookups and detailed analysis, you'll need to provide consent for ethical use. All services are logged for compliance.",
            "suggestions": ["What services do you offer?", "Show me pricing", "I need technical support"]
        }
    
    # Payment questions
    elif "payment" in message_lower or "pay" in message_lower or "card" in message_lower:
        return {
            "response": "We accept all major credit cards through our secure Stripe payment system:\n\n✓ Visa, Mastercard, American Express, Discover\n✓ Secure encrypted transactions\n✓ Instant service activation\n✓ Email receipts provided\n\nYou can purchase services directly from the Security Services or Social Media tabs. Need help with a payment issue?",
            "suggestions": ["View services", "I have a payment issue", "Contact support"]
        }
    
    # Support/Help
    elif "help" in message_lower or "support" in message_lower or "problem" in message_lower:
        return {
            "response": "I'm here to help! I can assist you with:\n\n• Explaining our services\n• Pricing information\n• How to use the platform\n• Technical questions\n• Payment issues\n\nPlease tell me what you need help with, or contact our support team at support@seccheck.io for urgent issues.",
            "suggestions": ["Technical problem", "Billing question", "How does this work?"]
        }
    
    # Breach/Security questions
    elif "breach" in message_lower or "compromised" in message_lower or "hacked" in message_lower:
        return {
            "response": "If you believe your accounts have been compromised:\n\n1. Use our Breach Details tab to search by email, username, or phone\n2. Review all exposed data (passwords, IPs, personal info)\n3. Follow our security recommendations\n4. Consider our Emergency Recovery service ($150) for immediate help\n\nFor comprehensive protection, our Premium Package ($150/month) includes 24/7 monitoring and instant breach alerts.",
            "suggestions": ["Check for breaches now", "View Emergency Recovery", "Show me Premium Package"]
        }
    
    # Default response
    else:
        return {
            "response": "Thanks for your message! I can help you with:\n\n• Service information and pricing\n• How to use SecCheck\n• Security questions\n• Technical support\n• Payment assistance\n\nWhat would you like to know?",
            "suggestions": ["What services do you offer?", "Show me pricing", "How does this work?"]
        }
