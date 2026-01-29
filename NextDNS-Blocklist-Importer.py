#!/usr/bin/env python3
"""
NextDNS FAST Bulk Denylist Importer for Pythonista (iOS)
========================================================
Uses PUT to upload the entire denylist in ONE request.
Works for lists of 20,000+ domains.

SETUP:
1. Get your API key from https://my.nextdns.io/account (scroll to bottom)
2. Get your Profile ID from the URL when viewing your profile
3. Fill in API_KEY and PROFILE_ID below
4. Run this script in Pythonista
"""

import requests
import re

# ============ CONFIGURE THESE ============
API_KEY = "NEXTDNS_API_KEY"      # From https://my.nextdns.io/account
PROFILE_ID = "NEXTDNS_PROFILE_ID"    # e.g., "abc123" from your NextDNS URL
# =========================================

# Blocklist URL(s) - add as many as you want
BLOCKLIST_URLS = [
    # "https://example.com/blocklist.txt",
    # Add more URLs here:
    # "https://example.com/another-blocklist.txt",
]

# API settings
API_BASE = "https://api.nextdns.io"


def fetch_blocklist(url):
    """Fetch a blocklist from URL."""
    print(f"   📥 {url.split('/')[-1]}")
    response = requests.get(url, timeout=60)
    response.raise_for_status()
    return response.text


def parse_domains(text):
    """
    Parse multiple blocklist formats:
    - AdGuard: ||domain.com^
    - Hosts file: 0.0.0.0 domain.com or 127.0.0.1 domain.com
    - Plain domains: domain.com
    """
    domains = set()
    
    for line in text.splitlines():
        line = line.strip()
        
        # Skip comments and empty lines
        if not line or line.startswith('!') or line.startswith('#'):
            continue
        
        domain = None
        
        # AdGuard format: ||domain.com^
        match = re.match(r'^\|\|([a-zA-Z0-9._-]+)\^?$', line)
        if match:
            domain = match.group(1)
        
        # Hosts file format: 0.0.0.0 domain.com or 127.0.0.1 domain.com
        if not domain:
            match = re.match(r'^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([a-zA-Z0-9._-]+)', line)
            if match:
                domain = match.group(1)
        
        # Plain domain format
        if not domain:
            match = re.match(r'^([a-zA-Z0-9][a-zA-Z0-9._-]*\.[a-zA-Z]{2,})$', line)
            if match:
                domain = match.group(1)
        
        # Validate and add
        if domain:
            domain = domain.lower().strip('.')
            # Skip localhost, empty, or too short
            if domain not in ('localhost', 'local', 'broadcasthost') and '.' in domain and len(domain) > 3:
                domains.add(domain)
    
    return domains


def get_current_denylist(api_key, profile_id):
    """GET the current denylist from NextDNS."""
    url = f"{API_BASE}/profiles/{profile_id}/denylist"
    headers = {"X-Api-Key": api_key}
    
    response = requests.get(url, headers=headers, timeout=30)
    response.raise_for_status()
    
    data = response.json()
    return data.get("data", [])


def put_denylist(api_key, profile_id, denylist):
    """PUT the entire denylist to NextDNS (replaces all)."""
    url = f"{API_BASE}/profiles/{profile_id}/denylist"
    headers = {
        "X-Api-Key": api_key,
        "Content-Type": "application/json"
    }
    
    response = requests.put(url, json=denylist, headers=headers, timeout=120)
    return response


def main():
    # Validate config
    if API_KEY == "YOUR_API_KEY_HERE" or PROFILE_ID == "YOUR_PROFILE_ID":
        print("❌ ERROR: Please configure API_KEY and PROFILE_ID at the top of this script!")
        print("\n   1. API Key: https://my.nextdns.io/account (scroll to bottom)")
        print("   2. Profile ID: The ID in your NextDNS URL (e.g., 'abc123')")
        return
    
    # Step 1: Fetch all blocklists
    print("📥 Fetching blocklists...")
    all_new_domains = set()
    
    for url in BLOCKLIST_URLS:
        try:
            raw_text = fetch_blocklist(url)
            domains = parse_domains(raw_text)
            all_new_domains.update(domains)
            print(f"      → {len(domains)} domains")
        except Exception as e:
            print(f"   ❌ Failed: {e}")
    
    print(f"\n✅ Total unique domains from blocklists: {len(all_new_domains)}")
    
    if not all_new_domains:
        print("❌ No domains found!")
        return
    
    # Step 2: Get current denylist
    print("\n📋 Fetching your current NextDNS denylist...")
    try:
        current_list = get_current_denylist(API_KEY, PROFILE_ID)
        current_domains = {item["id"] for item in current_list}
        print(f"   → Currently {len(current_domains)} domains in your denylist")
    except Exception as e:
        print(f"❌ Failed to fetch current denylist: {e}")
        return
    
    # Step 3: Merge (keep existing + add new)
    new_to_add = all_new_domains - current_domains
    print(f"\n📊 Summary:")
    print(f"   • Already in denylist: {len(all_new_domains & current_domains)}")
    print(f"   • New to add: {len(new_to_add)}")
    
    if not new_to_add:
        print("\n✅ All domains already in your denylist. Nothing to do!")
        return
    
    # Build combined list
    combined_list = list(current_list)  # Keep existing with their active states
    for domain in new_to_add:
        combined_list.append({"id": domain, "active": True})
    
    print(f"   • Final denylist size: {len(combined_list)}")
    
    # Confirm
    confirm = input("\n🚀 Upload merged denylist? (y/n): ").strip().lower()
    if confirm != 'y':
        print("Cancelled.")
        return
    
    # Step 4: PUT the entire list
    print("\n⏳ Uploading to NextDNS (single request)...")
    try:
        response = put_denylist(API_KEY, PROFILE_ID, combined_list)
        
        if response.status_code == 200:
            print("\n" + "=" * 40)
            print("✅ SUCCESS!")
            print("=" * 40)
            print(f"   Added {len(new_to_add)} new domains")
            print(f"   Total denylist: {len(combined_list)} domains")
            print(f"\n🔗 Check it out:")
            print(f"   https://my.nextdns.io/{PROFILE_ID}/denylist")
        else:
            print(f"\n❌ Failed with status {response.status_code}")
            print(f"   Response: {response.text[:500]}")
    except Exception as e:
        print(f"\n❌ Error: {e}")


if __name__ == "__main__":
    main()
