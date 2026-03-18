"""
Real Data Import and Management for SecCheck
Allows admin to import real breach data, social media accounts, etc.
"""

def create_sample_social_account(platform, username, email=None, phone=None):
    """Create a social media account record with profile picture"""
    
    profile_pics = {
        "Facebook": "https://graph.facebook.com/v12.0/me/picture?type=large",
        "Twitter": f"https://unavatar.io/twitter/{username}",
        "Instagram": f"https://unavatar.io/instagram/{username}",
        "LinkedIn": f"https://unavatar.io/linkedin/{username}",
        "TikTok": f"https://unavatar.io/{username}",
        "Reddit": f"https://www.redditstatic.com/avatars/defaults/v2/avatar_default_1.png",
        "GitHub": f"https://github.com/{username}.png",
        "Discord": "https://cdn.discordapp.com/embed/avatars/0.png"
    }
    
    return {
        "platform": platform,
        "username": username,
        "email": email,
        "phone": phone,
        "profile_picture": profile_pics.get(platform, "https://via.placeholder.com/150"),
        "profile_url": get_profile_url(platform, username),
        "created_date": "2020-01-01",
        "last_active": "2024-02-12",
        "followers": 1000,
        "compromised": False,
        "breach_date": None,
        "exposed_data": [],
        "password_found": False,
        "password_hash": None,
        "password_plaintext": None,
        "has_2fa": True
    }

def get_profile_url(platform, username):
    """Get profile URL for platform"""
    urls = {
        "Facebook": f"https://facebook.com/{username}",
        "Twitter": f"https://twitter.com/{username}",
        "Instagram": f"https://instagram.com/{username}",
        "LinkedIn": f"https://linkedin.com/in/{username}",
        "TikTok": f"https://tiktok.com/@{username}",
        "Reddit": f"https://reddit.com/user/{username}",
        "GitHub": f"https://github.com/{username}",
        "Discord": f"https://discord.com/users/{username}"
    }
    return urls.get(platform, f"https://{platform.lower()}.com/{username}")

def create_sample_breach_data():
    """Create sample breach data for testing"""
    return [
        {
            "email": "john.doe@example.com",
            "username": "johndoe",
            "phone": "+1-555-123-4567",
            "name": "John Doe",
            "all_emails": ["john.doe@example.com", "johndoe@gmail.com", "j.doe@company.com"],
            "all_usernames": ["johndoe", "john_doe", "jdoe123"],
            "compromised_passwords": [
                {
                    "source": "LinkedIn 2021",
                    "password_hash": "5f4dcc3b5aa765d61d8327deb882cf99",
                    "cracked": True,
                    "plaintext": "password123",
                    "first_seen": "2021-06-22",
                    "breach_size": "700M records"
                }
            ],
            "phone_records": ["+1-555-123-4567", "+1-555-987-6543"],
            "ip_addresses": [
                {
                    "ip": "192.168.1.100",
                    "location": "New York, US",
                    "breach_source": "LinkedIn 2021",
                    "last_seen": "2021-06-22"
                }
            ],
            "personal_info": {
                "full_name": "John Doe",
                "first_name": "John",
                "last_name": "Doe",
                "date_of_birth": "1990-05-15",
                "age": 34,
                "gender": "Male",
                "addresses": ["123 Main St, New York, NY 10001"]
            }
        }
    ]

async def import_social_accounts_bulk(db, accounts_data):
    """Import multiple social media accounts"""
    if not accounts_data:
        return {"imported": 0, "message": "No data provided"}
    
    result = await db.social_accounts.insert_many(accounts_data)
    return {
        "imported": len(result.inserted_ids),
        "message": f"Successfully imported {len(result.inserted_ids)} social media accounts"
    }

async def import_breach_data_bulk(db, breach_data):
    """Import breach data"""
    if not breach_data:
        return {"imported": 0, "message": "No data provided"}
    
    result = await db.breach_data.insert_many(breach_data)
    return {
        "imported": len(result.inserted_ids),
        "message": f"Successfully imported {len(result.inserted_ids)} breach records"
    }

async def clear_all_test_data(db):
    """Clear all test/sample data"""
    collections = ["social_accounts", "breach_data", "breach_details"]
    total_deleted = 0
    
    for collection in collections:
        result = await db[collection].delete_many({})
        total_deleted += result.deleted_count
    
    return {
        "deleted": total_deleted,
        "message": f"Cleared {total_deleted} records from {len(collections)} collections"
    }
